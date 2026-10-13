"""Native MOTD module after Base commit; no reimplementation of its installer."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import urllib.request

import transaction as tx
import network_recovery as net

bootstrap = sys.modules.get("bootstrap")
if bootstrap is None:
    raise RuntimeError("MOTD requires the trusted recovery loader")

PAYLOAD = "etc/update-motd.d/10-server-info"
COMMAND = "usr/local/bin/server-info"
FILES = ("install.sh", "VERSION", "SHA256SUMS", PAYLOAD, COMMAND)
PROJECT = "debian-server-info-motd"
WATCHED = ("/etc/update-motd.d", "/usr/local/bin/server-info", "/etc/motd", "/etc/issue",
           "/var/lib/" + PROJECT, "/etc/ssh/sshd_config.d/00-" + PROJECT + ".conf")
TERMINAL = tx.MODULE_FINAL_PHASES
PHASES = TERMINAL | {"prepared", "queued", "running"}
MUTATION_TIMEOUT = 90
CHECK_TIMEOUT = 40
LOG_TAIL = 16000


def validate_release(value: dict) -> dict:
    if (not isinstance(value, dict) or set(value) != {"repository", "source_ref", "commit", "version", "files"}
            or value["repository"] != bootstrap.MOTD_REPOSITORY
            or not isinstance(value["commit"], str) or not re.fullmatch(r"[0-9a-f]{40}", value["commit"])
            or not isinstance(value["version"], str) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", value["version"])
            or value["source_ref"] != "v" + value["version"]
            or not isinstance(value["files"], dict) or set(value["files"]) != set(FILES)
            or any(not isinstance(d, str) or not re.fullmatch(r"[0-9a-f]{64}", d) for d in value["files"].values())):
        raise tx.TransactionError("Invalid pinned MOTD release")
    return value


def protected_directory(path: Path, *, owner: int = 0) -> None:
    if not path.is_absolute() or path.resolve() != path:
        raise tx.TransactionError("MOTD source/root must be canonical")
    for current in (path, *path.parents):
        info = current.lstat()
        sticky_parent = current != path and bool(info.st_mode & stat.S_ISVTX)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != (owner if current == path else 0)
                or info.st_mode & 0o022 and not sticky_parent):
            raise tx.TransactionError("MOTD source/root parent is not protected")


class ReleaseSource:
    """A caller-owned protected tree, checked independently of its own manifest."""

    def __init__(self, directory: Path, *, release: dict | None = None, owner: int = 0):
        self.directory = Path(directory).absolute()
        self.release = copy.deepcopy(validate_release(release or bootstrap.MOTD_RELEASE))
        self.owner = owner  # Internal fixture injection; never a profile/CLI option.

    def inspect(self) -> dict:
        protected_directory(self.directory, owner=self.owner)
        filesystem = tx.RootFS(self.directory)
        result = {}
        for name in FILES:
            for parent in (self.directory / name).parents:
                if parent == self.directory:
                    break
                info = parent.lstat()
                if not stat.S_ISDIR(info.st_mode) or info.st_uid != self.owner or info.st_mode & 0o022:
                    raise tx.TransactionError("Unprotected MOTD source directory")
            value = filesystem.snapshot("/" + name)
            if (value["kind"] != "regular" or value["uid"] != self.owner or value["mode"] & 0o022
                    or value["sha256"] != self.release["files"][name]):
                raise tx.TransactionError("Pinned MOTD source checksum/ownership mismatch: " + name)
            result[name] = tx.fingerprint(value)
        if (self.directory / "VERSION").read_bytes() != (self.release["version"] + "\n").encode():
            raise tx.TransactionError("MOTD version differs from its pinned release")
        manifest = "".join(self.release["files"][name] + "  " + name + "\n" for name in ("VERSION", PAYLOAD, COMMAND))
        if (self.directory / "SHA256SUMS").read_bytes() != manifest.encode():
            raise tx.TransactionError("MOTD manifest differs from the independent release pins")
        for name in ("install.sh", PAYLOAD, COMMAND):
            result_check = subprocess.run(["/bin/bash", "-n", str(self.directory / name)],
                stdin=subprocess.DEVNULL, capture_output=True, timeout=10, check=False,
                env={"PATH": net.SYSTEM_PATH, "LC_ALL": "C"})
            if result_check.returncode:
                raise tx.TransactionError("Pinned MOTD source has invalid Bash syntax")
        return result


def stage_release(directory: Path) -> ReleaseSource:
    """Download only the fixed commit over HTTPS into a new private staging tree."""
    directory = Path(directory).absolute()
    protected_directory(directory.parent)
    directory.mkdir(mode=0o700)
    source = ReleaseSource(directory)
    filesystem = tx.RootFS(directory)
    for name in FILES:
        parent = directory / name
        for child in reversed(parent.parents):
            if directory in child.parents:
                child.mkdir(mode=0o700, exist_ok=True)
        url = "https://raw.githubusercontent.com/" + source.release["repository"] + "/" + source.release["commit"] + "/" + name
        with urllib.request.urlopen(url, timeout=20) as response:
            if response.geturl() != url:
                raise tx.TransactionError("Unexpected MOTD source redirect")
            data = response.read(tx.MAX_FILE_BYTES + 1)
        if len(data) > tx.MAX_FILE_BYTES or hashlib.sha256(data).hexdigest() != source.release["files"][name]:
            raise tx.TransactionError("Downloaded MOTD source differs from its pinned release")
        filesystem.replace("/" + name, tx.regular(data, 0o600, 0, 0), expected=tx.fingerprint({"kind": "absent"}))
    source.inspect()
    return source


def inventory(root: Path) -> dict:
    """Observe the module's paths without interpreting or restoring native state."""
    filesystem, result = tx.RootFS(root), {}
    def visit(path: str):
        if len(result) >= 128:
            raise tx.TransactionError("MOTD path inventory exceeds its limit")
        local = filesystem.root / path.lstrip("/")
        try:
            info = local.lstat()
        except FileNotFoundError:
            result[path] = tx.fingerprint({"kind": "absent"})
            return
        if stat.S_ISDIR(info.st_mode):
            # Pin the path chain before listing. Never recurse into a symlink.
            with filesystem.parent(path + "/.inventory") as (descriptor, _):
                opened = os.fstat(descriptor)
                if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                    raise tx.StalePlan("MOTD directory changed while opening")
                names = sorted(os.listdir(descriptor))
            result[path] = {"kind": "directory", "mode": stat.S_IMODE(info.st_mode), "uid": info.st_uid,
                            "gid": info.st_gid, "inode": info.st_ino, "device": info.st_dev}
            for name in names:
                tx.safe_path(path + "/" + name)
                visit(path + "/" + name)
        else:
            result[path] = tx.fingerprint(filesystem.snapshot(path))
    for path in WATCHED:
        visit(path)
    return result


def contents(value: dict) -> dict:
    # Native rollback may replace an inode. Compare content/type/ownership/mode
    # and regular-file mtime, without claiming ownership of directory inodes.
    return {p: {k: v for k, v in item.items() if k not in {"inode", "device"}}
            for p, item in value.items()}


def validate_health(value: dict) -> dict:
    if not isinstance(value, dict) or set(value) != {"code", "data"} or type(value["code"]) is not int:
        raise tx.TransactionError("Invalid native MOTD health result")
    data, code = value["data"], value["code"]
    if (code not in {0, 3, 4, 5} or not isinstance(data, dict) or data.get("schema_version") != 1
            or any(type(data.get(k)) is not bool for k in ("installed", "healthy", "desired_source_matches"))):
        raise tx.TransactionError("Native MOTD check failed or returned invalid JSON")
    if code == 3:
        if data != {"schema_version": 1, "installed": False, "healthy": False, "desired_source_matches": False}:
            raise tx.TransactionError("Invalid native absent-state result")
    elif (not data["installed"] or data["healthy"] != (code in {0, 5})
          or code in {0, 5} and data["desired_source_matches"] != (code == 0)
          or any(not isinstance(data.get(k), str) for k in ("source_ref", "version", "payload_sha256", "command_sha256",
                                                           "target_status", "command_status", "last_login_status"))
          or type(data.get("last_login_managed")) is not bool):
        raise tx.TransactionError("Inconsistent native MOTD health result")
    if code != 3 and (set(data) != {"schema_version", "installed", "healthy", "desired_source_matches", "source_ref", "version",
                                   "payload_sha256", "command_sha256", "target_status", "command_status", "last_login_managed", "last_login_status"}
                      or any(not re.fullmatch(r"[0-9a-f]{64}", data[k]) for k in ("payload_sha256", "command_sha256"))
                      or any(len(data[k]) > 256 for k in ("source_ref", "version", "target_status", "command_status", "last_login_status"))):
        raise tx.TransactionError("Invalid native managed MOTD details")
    return value


def desired_health(value: dict, release: dict) -> bool:
    data = validate_health(value)["data"]
    return (value["code"] == 0 and data.get("source_ref") == release["source_ref"]
            and data.get("version") == release["version"]
            and data.get("payload_sha256") == release["files"][PAYLOAD]
            and data.get("command_sha256") == release["files"][COMMAND])


class NativeBackend:
    def __init__(self, root: Path, *, namespace: str | None = None):
        self.root = Path(root).absolute()
        if namespace is not None and (not net.NAMESPACE.fullmatch(namespace) or self.root == Path("/")):
            raise tx.TransactionError("Invalid MOTD fixture namespace")
        self.namespace = namespace

    def prefix(self) -> list[str]:
        if self.namespace is None:
            return []
        import base_apply
        hostname = base_apply.HostnameBackend(self.root)
        hostname.identity()
        return ["/usr/sbin/ip", "netns", "exec", self.namespace, "/usr/bin/nsenter", "--uts=" + str(hostname.namespace)]

    def command(self, arguments: list[str], *, timeout: int) -> dict:
        protected_directory(self.root)
        with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
            result = subprocess.run([*self.prefix(), *arguments], stdin=subprocess.DEVNULL, stdout=output, stderr=errors,
                timeout=timeout, check=False, env={"PATH": net.SYSTEM_PATH, "LC_ALL": "C"}, close_fds=True)
            size, error_size = output.tell(), errors.tell()
            output.seek(max(0, size - LOG_TAIL))
            errors.seek(max(0, error_size - LOG_TAIL))
            return {"returncode": result.returncode, "output": output.read().decode(errors="replace"),
                    "errors": errors.read().decode(errors="replace"), "truncated": max(size, error_size) > LOG_TAIL}

    def check(self, source: ReleaseSource) -> dict:
        source.inspect()
        result = self.command(["/bin/bash", str(source.directory / "install.sh"), "--check",
                               "--source-ref", source.release["source_ref"], "--root", str(self.root)], timeout=CHECK_TIMEOUT)
        if result["truncated"]:
            raise tx.TransactionError("Native MOTD check exceeds its output limit")
        try:
            data = json.loads(result["output"], object_pairs_hook=tx.unique_keys)
        except (ValueError, UnicodeError) as error:
            raise tx.TransactionError("Native MOTD check did not return valid JSON") from error
        return validate_health({"code": result["returncode"], "data": data})

    def run(self, source: ReleaseSource, action: str, run_id: str) -> dict:
        if self.root == Path("/"):
            raise tx.TransactionError("Production MOTD module application remains gated")
        if action not in {"install", "update", "repair"}:
            raise tx.TransactionError("Invalid native MOTD mutation")
        tx.FileTransaction._run_id(run_id)
        source.inspect()
        protected_directory(self.root)
        # Mutating --root is deliberately unsupported by the native installer.
        # Copy only its verified source into the committed disposable target and
        # run that unmodified installer in chroot, using its documented API.
        parent = self.root / "var/lib/rzandal-bootstrap-motd-sources"
        parent.mkdir(mode=0o700, exist_ok=True)
        protected_directory(parent)
        directory = parent / run_id
        directory.mkdir(mode=0o700)
        filesystem = tx.RootFS(directory)
        for name in FILES:
            for child in reversed((directory / name).parents):
                if directory in child.parents:
                    child.mkdir(mode=0o700, exist_ok=True)
            value = tx.RootFS(source.directory).snapshot("/" + name)
            filesystem.replace("/" + name, tx.regular(base64.b64decode(value["data"]), 0o600, 0, 0),
                               expected=tx.fingerprint({"kind": "absent"}))
        staged = ReleaseSource(directory, release=source.release)
        staged.inspect()
        target = "/var/lib/rzandal-bootstrap-motd-sources/" + run_id
        return self.command(["/usr/sbin/chroot", str(self.root), "/bin/bash", target + "/install.sh",
                             "--" + action, "--source-ref", source.release["source_ref"], "--source-directory", target],
                            timeout=MUTATION_TIMEOUT)


def prepare_plan(source: ReleaseSource, backend: NativeBackend) -> dict:
    hashes = source.inspect()
    before = inventory(backend.root)
    checked = backend.check(source)
    if before != inventory(backend.root) or hashes != source.inspect():
        raise tx.StalePlan("MOTD source/state changed while reviewing")
    if checked["code"] == 0 and not desired_health(checked, source.release):
        raise tx.TransactionError("Matching native source ref has unexpected payload/version; review it manually")
    return {"schema_version": 1, "release": source.release, "source_directory": str(source.directory),
            "source_fingerprints": hashes, "before": checked, "watched": before,
            "action": {0: "check", 3: "install", 4: "repair", 5: "update"}[checked["code"]]}


def validate_plan(value: dict) -> dict:
    if (not isinstance(value, dict) or set(value) != {"schema_version", "release", "source_directory", "source_fingerprints",
                                                    "before", "watched", "action"} or value["schema_version"] != 1
            or not isinstance(value["source_directory"], str) or not isinstance(value["watched"], dict)
            or len(value["watched"]) > 128 or not isinstance(value["source_fingerprints"], dict)
            or set(value["source_fingerprints"]) != set(FILES)):
        raise tx.TransactionError("Invalid reviewed MOTD plan")
    tx.safe_path(value["source_directory"])
    validate_release(value["release"])
    validate_health(value["before"])
    if value["action"] != {0: "check", 3: "install", 4: "repair", 5: "update"}[value["before"]["code"]]:
        raise tx.TransactionError("MOTD action differs from its reviewed native health")
    if value["action"] == "check" and not desired_health(value["before"], value["release"]):
        raise tx.TransactionError("MOTD no-op is not the pinned healthy release")
    for name, fp in value["source_fingerprints"].items():
        if not isinstance(fp, dict) or fp.get("sha256") != value["release"]["files"][name]:
            raise tx.TransactionError("Reviewed MOTD source differs from its independent pins")
    for path, fp in value["watched"].items():
        tx.safe_path(path)
        if (not any(path == p or path.startswith(p + "/") for p in WATCHED)
                or not isinstance(fp, dict) or fp.get("kind") not in {"regular", "symlink", "absent", "directory"}):
            raise tx.TransactionError("Invalid watched MOTD path")
    if not set(WATCHED) <= set(value["watched"]):
        raise tx.TransactionError("Incomplete watched MOTD inventory")
    return value


class Module:
    def __init__(self, manager: tx.FileTransaction, run_id: str, backend: NativeBackend):
        manager._run_id(run_id)
        self.manager, self.run_id, self.backend = manager, run_id, backend
        self.path = f"/runs/{run_id}/motd.json"

    def source(self, plan: dict) -> ReleaseSource:
        return ReleaseSource(self.manager.state_dir / "runs" / self.run_id / "motd-source", release=plan["release"],
                             owner=self.manager.owner)

    def prepare_locked(self, plan: dict) -> None:
        validate_plan(plan)
        source = ReleaseSource(Path(plan["source_directory"]), release=plan["release"], owner=self.manager.owner)
        if (source.inspect() != plan["source_fingerprints"] or inventory(self.backend.root) != plan["watched"]
                or self.backend.check(source) != plan["before"]):
            raise tx.StalePlan("MOTD source/state changed after its review")
        if self.manager.store.snapshot(self.path)["kind"] != "absent":
            raise tx.TransactionError("MOTD journal already exists")
        destination = self.source(plan)
        self.manager._directory(destination.directory, create=True)
        for name in FILES:
            for child in reversed((destination.directory / name).parents):
                if destination.directory in child.parents:
                    self.manager._directory(child, create=True)
            value = tx.RootFS(source.directory).snapshot("/" + name)
            self.manager.store.replace(f"/runs/{self.run_id}/motd-source/" + name,
                tx.regular(base64.b64decode(value["data"]), 0o600, self.manager.owner, self.manager.group),
                expected=tx.fingerprint({"kind": "absent"}))
        destination.inspect()
        self.manager._save(self.path, {"schema_version": 1, "run_id": self.run_id, "plan": plan, "phase": "prepared",
                                      "manual_attention": False, "result": None, "health": None, "reason": None})

    def load(self) -> dict:
        value = self.manager._load(self.path)
        if (value.get("schema_version") != 1 or value.get("run_id") != self.run_id or value.get("phase") not in PHASES
                or type(value.get("manual_attention")) is not bool):
            raise tx.TransactionError("Invalid MOTD module journal")
        validate_plan(value.get("plan"))
        return value

    def verify_before_locked(self) -> None:
        value = self.load()
        self.source(value["plan"]).inspect()
        if (value["phase"] not in {"prepared", "queued"} or inventory(self.backend.root) != value["plan"]["watched"]
                or self.backend.check(self.source(value["plan"])) != value["plan"]["before"]):
            raise tx.StalePlan("MOTD state changed before native installation")
        if self.manager._module_active() != self.run_id:
            raise tx.TransactionError("MOTD lost its Base/module reservation")

    def queue_locked(self) -> bool:
        value = self.load()
        if value["phase"] == "prepared":
            value["phase"] = "queued"
            self.manager._save(self.path, value)
        return value["phase"] == "queued"

    def fail_locked(self, reason: str) -> None:
        value = self.load()
        value.update(phase="failed", manual_attention=True, reason=reason[:LOG_TAIL])
        self.manager._save(self.path, value)

    def run_locked(self) -> None:
        value = self.load()
        if value["phase"] in TERMINAL:
            return
        if value["phase"] != "queued":
            raise tx.TransactionError("MOTD requires a committed queued run")
        self.verify_before_locked()
        value["phase"] = "running"
        self.manager._save(self.path, value)  # Durable intent before the native writer.
        source, plan = self.source(value["plan"]), value["plan"]
        result = None
        if plan["action"] != "check":
            result = self.backend.run(source, plan["action"], self.run_id)
            value["result"] = result
            self.manager._save(self.path, value)
        try:
            health = self.backend.check(source)
            value["health"] = health
            if (result is None or result["returncode"] == 0) and desired_health(health, plan["release"]):
                value["phase"] = "completed"
            else:
                value["phase"] = "failed"
                value["reason"] = "Native MOTD did not complete the pinned healthy release"
                value["manual_attention"] = contents(inventory(self.backend.root)) != contents(plan["watched"])
        except (tx.TransactionError, OSError, ValueError, subprocess.SubprocessError) as error:
            value.update(phase="failed", manual_attention=True, reason=str(error)[:LOG_TAIL])
        self.manager._save(self.path, value)

    def observe_locked(self, base_phase: str) -> None:
        value = self.load()
        if value["phase"] in TERMINAL:
            return
        if base_phase != "committed":
            if value["phase"] != "prepared":
                raise tx.TransactionError("MOTD writer cannot precede Base commit")
            value["phase"] = "cancelled"
        else:
            value.update(phase="interrupted", manual_attention=True,
                         reason="MOTD execution was interrupted; native mutation is never retried automatically")
            try:
                value["health"] = self.backend.check(self.source(value["plan"]))
            except (tx.TransactionError, OSError, ValueError, subprocess.SubprocessError) as error:
                value["reason"] += ": " + str(error)[:LOG_TAIL]
        self.manager._save(self.path, value)

    def status(self) -> dict:
        value = self.load()
        return {"phase": value["phase"], "action": value["plan"]["action"], "source_ref": value["plan"]["release"]["source_ref"],
                "version": value["plan"]["release"]["version"], "manual_attention": value["manual_attention"],
                "health": value["health"], "result": value["result"], "reason": value["reason"], "base_policy": "preserved"}
