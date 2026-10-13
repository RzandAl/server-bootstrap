"""Durable file transactions for the future apply supervisor.

This module does not change live networking or run packages. The bootstrap CLI
does not call its write API yet. The only command-line operations are status and
manual file recovery; automatic network recovery remains a separate milestone.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import copy
import fcntl
import glob
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import time
from typing import Any, Callable, Iterator
import uuid


STATE_DIRECTORY = Path("/var/lib/rzandal-server-bootstrap")
MAX_FILE_BYTES = 1024 * 1024
MAX_STATE_BYTES = 32 * MAX_FILE_BYTES
MAX_CHANGED_FILES = 128
RUN_ID = re.compile(r"[0-9a-f]{32}\Z")
FINAL_PHASES = {"committed", "rolled_back"}
MODULE_FINAL_PHASES = {"completed", "failed", "interrupted", "cancelled"}
PHASES = FINAL_PHASES | {"prepared", "applying", "applied", "rolling_back", "recovery_failed"}
FINGERPRINT_KEYS = ("kind", "sha256", "target", "mode", "uid", "gid", "inode", "device", "mtime_ns")
DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


class TransactionError(ValueError):
    """Stop before guessing, overwriting an external edit, or losing recovery data."""


class StalePlan(TransactionError):
    pass


class BusyRun(TransactionError):
    pass


class RecoveryError(TransactionError):
    pass


def safe_path(path: str) -> tuple[str, ...]:
    if (not isinstance(path, str) or not path.startswith("/") or path == "/"
            or PurePosixPath(path).as_posix() != path or ".." in PurePosixPath(path).parts
            or any(character in path for character in "\0\r\n")):
        raise TransactionError(f"Unsafe file path: {path!r}")
    return PurePosixPath(path).parts[1:]


def fingerprint(snapshot: dict[str, Any]) -> dict[str, Any]:
    return {key: snapshot.get(key) for key in FINGERPRINT_KEYS}


def same_file(left: dict[str, Any], right: dict[str, Any]) -> bool:
    """Compare content/type/ownership, not the inode assigned by atomic replace."""
    return all(left.get(key) == right.get(key) for key in FINGERPRINT_KEYS[:6])


def regular(data: bytes, mode: int, uid: int, gid: int) -> dict[str, Any]:
    return {"kind": "regular", "data": base64.b64encode(data).decode("ascii"),
            "sha256": hashlib.sha256(data).hexdigest(), "target": None,
            "mode": mode, "uid": uid, "gid": gid}


def validate_snapshot(snapshot: dict[str, Any], *, max_bytes: int = MAX_FILE_BYTES) -> None:
    if not isinstance(snapshot, dict) or snapshot.get("kind") not in {"regular", "symlink", "absent"}:
        raise TransactionError("Invalid file snapshot")
    if snapshot["kind"] == "absent":
        if any(value is not None for key, value in snapshot.items() if key != "kind"):
            raise TransactionError("Absent file has unexpected payload or metadata")
        return
    for key in ("uid", "gid", "mode"):
        value = snapshot.get(key)
        if type(value) is not int or value < 0 or value > (0o777 if key == "mode" else 2**32 - 2):
            raise TransactionError(f"Invalid file {key}")
    if snapshot["kind"] == "regular":
        try:
            data = base64.b64decode(snapshot["data"], validate=True)
        except (KeyError, ValueError, TypeError) as error:
            raise TransactionError("Invalid backup encoding") from error
        if len(data) > max_bytes or hashlib.sha256(data).hexdigest() != snapshot.get("sha256"):
            raise TransactionError("Backup or candidate checksum mismatch")
        if snapshot.get("target") is not None:
            raise TransactionError("Regular file has a symlink target")
    else:
        target = snapshot.get("target")
        if (not isinstance(target, str) or not target or len(target.encode()) > 4096
                or any(c in target for c in "\0\r\n")):
            raise TransactionError("Invalid symlink target")
        if snapshot.get("sha256") is not None or snapshot.get("data") is not None:
            raise TransactionError("Symlink has regular-file data")
    for key in ("mtime_ns", "inode", "device"):
        if key in snapshot and (type(snapshot[key]) is not int or snapshot[key] < 0):
            raise TransactionError(f"Invalid snapshot {key}")


class RootFS:
    """Use pinned parent directory descriptors; never follow a target symlink."""

    def __init__(self, root: Path = Path("/"), *, max_bytes: int = MAX_FILE_BYTES):
        self.root = Path(root).absolute()
        self.max_bytes = max_bytes

    @contextlib.contextmanager
    def parent(self, path: str) -> Iterator[tuple[int, str]]:
        parts = safe_path(path)
        descriptor = os.open(self.root, DIRECTORY_FLAGS)
        try:
            for part in parts[:-1]:
                next_descriptor = os.open(part, DIRECTORY_FLAGS, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = next_descriptor
            yield descriptor, parts[-1]
        finally:
            os.close(descriptor)

    def _snapshot_at(self, descriptor: int, name: str) -> dict[str, Any]:
        try:
            info = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        except FileNotFoundError:
            return {"kind": "absent"}
        attributes = {"mode": stat.S_IMODE(info.st_mode), "uid": info.st_uid, "gid": info.st_gid,
                      "inode": info.st_ino, "device": info.st_dev, "mtime_ns": info.st_mtime_ns}
        if stat.S_ISLNK(info.st_mode):
            result = {"kind": "symlink", "target": os.readlink(name, dir_fd=descriptor),
                      "sha256": None, **attributes}
        elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= self.max_bytes:
            file_descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                                      dir_fd=descriptor)
            with os.fdopen(file_descriptor, "rb") as stream:
                keys = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_size", "st_mtime_ns", "st_ctime_ns")
                opened = os.fstat(stream.fileno())
                if any(getattr(opened, key) != getattr(info, key) for key in keys):
                    raise StalePlan(f"{name}: changed while opening")
                if os.listxattr(stream.fileno()):
                    raise TransactionError(f"{name}: extended attributes/ACLs require a preservation backend")
                data = stream.read(self.max_bytes + 1)
                after = os.fstat(stream.fileno())
                if len(data) > self.max_bytes or any(getattr(after, key) != getattr(info, key) for key in keys):
                    raise StalePlan(f"{name}: changed while reading")
            result = regular(data, attributes.pop("mode"), attributes.pop("uid"), attributes.pop("gid"))
            result.update(attributes)
        else:
            raise TransactionError(f"{name}: special, oversized, or hard-linked file")
        if stat.S_ISLNK(info.st_mode) and os.listxattr(f"/proc/self/fd/{descriptor}/{name}", follow_symlinks=False):
            raise TransactionError(f"{name}: symlink extended attributes require review")
        # Reading may update atime; compare the fields which describe the object.
        after = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        keys = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_size", "st_mtime_ns", "st_ctime_ns")
        if any(getattr(after, key) != getattr(info, key) for key in keys):
            raise StalePlan(f"{name}: changed while inspecting")
        return result

    def snapshot(self, path: str) -> dict[str, Any]:
        try:
            with self.parent(path) as (descriptor, name):
                return self._snapshot_at(descriptor, name)
        except FileNotFoundError:
            return {"kind": "absent"}

    def replace(self, path: str, value: dict[str, Any], *, expected: dict[str, Any],
                restore_time: bool = False) -> None:
        validate_snapshot(value, max_bytes=self.max_bytes)
        with self.parent(path) as (descriptor, name):
            temporary = ".rzandal-" + uuid.uuid4().hex
            try:
                if value["kind"] == "regular":
                    file_descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                                              | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=descriptor)
                    with os.fdopen(file_descriptor, "wb") as stream:
                        os.fchown(stream.fileno(), value["uid"], value["gid"])
                        os.fchmod(stream.fileno(), value["mode"])
                        if os.listxattr(stream.fileno()):
                            raise TransactionError(f"{path}: inherited extended attributes/ACLs require review")
                        stream.write(base64.b64decode(value["data"], validate=True))
                        stream.flush()
                        if restore_time and "mtime_ns" in value:
                            os.utime(stream.fileno(), ns=(value["mtime_ns"], value["mtime_ns"]))
                        os.fsync(stream.fileno())
                elif value["kind"] == "symlink":
                    os.symlink(value["target"], temporary, dir_fd=descriptor)
                    os.chown(temporary, value["uid"], value["gid"], dir_fd=descriptor, follow_symlinks=False)
                    if restore_time and "mtime_ns" in value:
                        os.utime(temporary, ns=(value["mtime_ns"], value["mtime_ns"]),
                                 dir_fd=descriptor, follow_symlinks=False)
                if fingerprint(self._snapshot_at(descriptor, name)) != expected:
                    raise StalePlan(f"{path}: changed before replacement")
                if value["kind"] == "absent":
                    if expected["kind"] != "absent":
                        os.unlink(name, dir_fd=descriptor)
                else:
                    os.replace(temporary, name, src_dir_fd=descriptor, dst_dir_fd=descriptor)
                os.fsync(descriptor)
            finally:
                try:
                    os.unlink(temporary, dir_fd=descriptor)
                except FileNotFoundError:
                    pass


def encoded_json(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":")) + "\n").encode()


def plan_digest(report: dict[str, Any]) -> str:
    return hashlib.sha256(encoded_json(report)).hexdigest()


def unique_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise TransactionError(f"Duplicate journal key: {key}")
        result[key] = value
    return result


class FileTransaction:
    """Internal file backend. Call only after authorization and recovery arming.

    An alternate root/state directory is dependency injection for isolated tests,
    not a CLI option. No timeout, SSH acknowledgment, or live-network operation
    is implemented here; the future supervisor must supply those guarantees.
    """

    def __init__(self, *, root: Path = Path("/"), state_dir: Path = STATE_DIRECTORY, lock_timeout: float = 0):
        if type(lock_timeout) not in (int, float) or not 0 <= lock_timeout <= 5:
            raise TransactionError("Internal lock wait must be between zero and five seconds")
        self.lock_timeout = lock_timeout
        self.fs = RootFS(root)
        self.state_dir = Path(state_dir).absolute()
        self.store = RootFS(self.state_dir, max_bytes=MAX_STATE_BYTES)
        self.owner = os.geteuid()
        self.group = os.getegid()
        if self.fs.root == Path("/") and self.owner != 0:
            raise TransactionError("System transactions require root")
        # A target root cannot also serve as the private state directory.
        if self.state_dir == self.fs.root:
            raise TransactionError("State directory cannot be the target root")

    def _directory(self, path: Path, *, create: bool) -> None:
        filesystem = RootFS(Path("/"))
        with filesystem.parent(str(path)) as (descriptor, name):
            if create:
                try:
                    os.mkdir(name, 0o700, dir_fd=descriptor)
                    os.fsync(descriptor)
                except FileExistsError:
                    pass
            opened = os.open(name, DIRECTORY_FLAGS, dir_fd=descriptor)
            try:
                info = os.fstat(opened)
                if info.st_uid != self.owner or stat.S_IMODE(info.st_mode) != 0o700:
                    raise TransactionError(f"{path}: state requires owner UID {self.owner} and mode 0700")
            finally:
                os.close(opened)

    @contextlib.contextmanager
    def _lock(self, *, create: bool = False) -> Iterator[None]:
        self._directory(self.state_dir, create=create)
        with self.store.parent("/lock") as (descriptor, name):
            flags = os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
            lock = os.open(name, flags | (os.O_CREAT if create else 0), 0o600, dir_fd=descriptor)
            try:
                info = os.fstat(lock)
                if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != self.owner
                        or stat.S_IMODE(info.st_mode) != 0o600):
                    raise TransactionError("Unsafe transaction lock")
                deadline = time.monotonic() + self.lock_timeout
                while True:
                    try:
                        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        break
                    except BlockingIOError as error:
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            raise BusyRun("Another transaction or recovery process holds the lock") from error
                        time.sleep(min(0.02, remaining))
                if create:
                    os.fsync(lock)
                    os.fsync(descriptor)
                yield
            finally:
                os.close(lock)

    def _save(self, path: str, value: Any) -> None:
        if not isinstance(value, dict) or "_sha256" in value:
            raise TransactionError("State must be an object without reserved checksum fields")
        data = encoded_json({**value, "_sha256": hashlib.sha256(encoded_json(value)).hexdigest()})
        if len(data) > MAX_STATE_BYTES:
            raise TransactionError("Transaction state is too large")
        before = self.store.snapshot(path)
        self._private(before, absent=True)
        self.store.replace(path, regular(data, 0o600, self.owner, self.group), expected=fingerprint(before))

    def _private(self, snapshot: dict[str, Any], *, absent: bool = False) -> None:
        if absent and snapshot["kind"] == "absent":
            return
        if (snapshot["kind"] != "regular" or snapshot["uid"] != self.owner
                or snapshot["mode"] != 0o600):
            raise TransactionError("Journal must be a private, owned regular file")

    def _load(self, path: str) -> Any:
        snapshot = self.store.snapshot(path)
        self._private(snapshot)
        try:
            value = json.loads(base64.b64decode(snapshot["data"]), object_pairs_hook=unique_keys)
        except (ValueError, UnicodeError) as error:
            raise TransactionError(f"{path}: invalid transaction JSON") from error
        if not isinstance(value, dict):
            raise TransactionError(f"{path}: state must be a JSON object")
        digest = value.pop("_sha256", None)
        if digest != hashlib.sha256(encoded_json(value)).hexdigest():
            raise TransactionError(f"{path}: state checksum mismatch")
        return value

    def _active(self) -> str | None:
        if self.store.snapshot("/active.json")["kind"] == "absent":
            return None
        value = self._load("/active.json")
        if not isinstance(value, dict) or set(value) != {"run_id"}:
            raise TransactionError("Invalid active-run pointer")
        self._run_id(value["run_id"])
        return value["run_id"]

    @staticmethod
    def _run_id(run_id: str) -> None:
        if not isinstance(run_id, str) or not RUN_ID.fullmatch(run_id):
            raise TransactionError("Run ID must contain exactly 32 lowercase hexadecimal characters")

    def _run(self, run_id: str) -> tuple[dict[str, Any], dict[str, Any]]:
        self._run_id(run_id)
        self._directory(self.state_dir / "runs", create=False)
        self._directory(self.state_dir / "runs" / run_id, create=False)
        backup = self._load(f"/runs/{run_id}/backup.json")
        journal = self._load(f"/runs/{run_id}/journal.json")
        if (not isinstance(backup, dict) or backup.get("schema_version") != 1
                or backup.get("run_id") != run_id or not isinstance(backup.get("files"), list)
                or not (0 < len(backup["files"]) <= MAX_CHANGED_FILES
                        or len(backup["files"]) == 0 and backup.get("nonfile_run") is True)
                or "nonfile_run" in backup and type(backup["nonfile_run"]) is not bool):
            raise TransactionError("Invalid backup manifest")
        paths = []
        for entry in backup["files"]:
            if not isinstance(entry, dict) or set(entry) != {"path", "before", "after"}:
                raise TransactionError("Invalid backup entry")
            safe_path(entry["path"])
            paths.append(entry["path"])
            for key in ("before", "after"):
                validate_snapshot(entry[key])
        if len(set(paths)) != len(paths):
            raise TransactionError("Duplicate backup paths")
        if (not isinstance(journal, dict) or journal.get("run_id") != run_id
                or not isinstance(journal.get("phase"), str) or journal["phase"] not in PHASES
                or not isinstance(journal.get("attempted"), list)
                or journal.get("backup_sha256") != hashlib.sha256(encoded_json(backup)).hexdigest()
                or any(not isinstance(path, str) or path not in paths for path in journal["attempted"])
                or len(set(journal["attempted"])) != len(journal["attempted"])):
            raise TransactionError("Invalid journal or backup checksum")
        attempted = journal["attempted"]
        if "supervised" in journal and type(journal["supervised"]) is not bool:
            raise TransactionError("Invalid supervisor marker")
        if (attempted != paths[:len(attempted)]
                or (journal["phase"] == "prepared" and attempted)
                or (journal["phase"] in {"applied", "committed"} and attempted != paths)):
            raise TransactionError("Journal write intent is inconsistent with its phase")
        return backup, journal

    def _clear(self, run_id: str) -> None:
        if self._active() == run_id:
            current = self.store.snapshot("/active.json")
            self.store.replace("/active.json", {"kind": "absent"}, expected=fingerprint(current))

    def _available(self) -> None:
        module = self._module_active()
        if module is not None:
            value = self._load(f"/runs/{module}/motd.json")
            if value.get("run_id") != module or value.get("phase") not in MODULE_FINAL_PHASES:
                raise BusyRun(f"Run {module} has an unresolved MOTD module; inspect or recover it before another run")
            self._clear_module(module)
        active = self._active()
        if active is not None:
            _, journal = self._run(active)
            if journal["phase"] not in FINAL_PHASES:
                raise BusyRun(f"Run {active} needs recovery before another run can start")
            self._clear(active)

    def _module_active(self) -> str | None:
        if self.store.snapshot("/module-active.json")["kind"] == "absent":
            return None
        value = self._load("/module-active.json")
        if not isinstance(value, dict) or set(value) != {"run_id"}:
            raise TransactionError("Invalid active module pointer")
        self._run_id(value["run_id"])
        return value["run_id"]

    def _reserve_module(self, run_id: str) -> None:
        self._run_id(run_id)
        if self._active() != run_id or self._module_active() is not None:
            raise BusyRun("MOTD module needs its active Base reservation")
        self._save("/module-active.json", {"run_id": run_id})

    def _clear_module(self, run_id: str) -> None:
        current = self._module_active()
        if current is not None and current != run_id:
            raise TransactionError("Another module's reservation must be preserved")
        if current == run_id:
            before = self.store.snapshot("/module-active.json")
            self.store.replace("/module-active.json", {"kind": "absent"}, expected=fingerprint(before))

    def _verify_watched(self, report: dict[str, Any]) -> None:
        for path, expected in report["watched_files"].items():
            if fingerprint(self.fs.snapshot(path)) != expected:
                raise StalePlan(f"{path}: inspected file changed")
        for pattern, expected in report.get("watched_patterns", {}).items():
            safe_path(pattern)
            found = sorted("/" + str(Path(path).relative_to(self.fs.root))
                           for path in glob.glob(str(self.fs.root / pattern.lstrip("/"))))
            if found != expected:
                raise StalePlan(f"{pattern}: inspected directory inventory changed")

    def prepare(self, report: dict[str, Any], *, refresh: Callable[[], dict[str, Any]],
                force_run: bool = False) -> str | None:
        """Re-audit under the lock and durably save originals before any target write."""
        report = copy.deepcopy(report)
        if report.get("file_plan_available") is not True or report.get("blockers") != []:
            raise TransactionError("A complete, unblocked host plan is required")
        files = report.get("files")
        watched = report.get("watched_files")
        if not isinstance(files, list) or not isinstance(watched, dict):
            raise TransactionError("Missing file candidates or fingerprints")
        if plan_digest(refresh()) != plan_digest(report):
            raise StalePlan("Host plan changed; collect and review a new plan")
        self._verify_watched(report)
        entries = []
        paths = set()
        for entry in files:
            path = entry["path"]
            safe_path(path)
            local = self.fs.root / path.lstrip("/")
            if local == self.state_dir or self.state_dir in local.parents:
                raise TransactionError("A candidate cannot overwrite transaction state")
            if path in paths or type(entry.get("changed")) is not bool:
                raise TransactionError("Duplicate candidate or invalid change flag")
            paths.add(path)
            if entry["before"] != watched.get(path):
                raise TransactionError("Candidate does not match inspected fingerprint")
            after = entry["after"]
            if after["kind"] == "regular":
                value = regular(after["content"].encode("utf-8"), after["mode"], after["uid"], after["gid"])
                if value["sha256"] != after["sha256"]:
                    raise TransactionError("Candidate checksum mismatch")
            elif after["kind"] == "symlink":
                value = {"kind": "symlink", "target": after["target"], "mode": 0o777,
                         "uid": after["uid"], "gid": after["gid"], "sha256": None}
            else:
                raise TransactionError("Unsupported candidate type")
            validate_snapshot(value)
            if entry["changed"] == same_file(entry["before"], value):
                raise TransactionError("Candidate change flag does not match its content or metadata")
            if entry["changed"]:
                entries.append({"path": path, "after": value})
        if type(force_run) is not bool:
            raise TransactionError("Invalid non-file transaction selection")
        if not entries and not force_run:
            try:
                self.state_dir.lstat()
            except FileNotFoundError:
                pass
            else:
                with self._lock():
                    self._available()
            return None  # No state directory, lock file, journal, backup, or target rewrite.
        if len(entries) > MAX_CHANGED_FILES:
            raise TransactionError("Too many changed files")
        with self._lock(create=True):
            self._available()
            if plan_digest(refresh()) != plan_digest(report):
                raise StalePlan("Host plan changed while acquiring the lock")
            # Independently reread bytes and metadata; the callback cannot substitute
            # a fresh filesystem snapshot by returning the old report object.
            self._verify_watched(report)
            for entry in entries:
                entry["before"] = self.fs.snapshot(entry["path"])
                validate_snapshot(entry["before"])
                if fingerprint(entry["before"]) != watched[entry["path"]]:
                    raise StalePlan(f"{entry['path']}: changed before backup")
            run_id = uuid.uuid4().hex
            self._directory(self.state_dir / "runs", create=True)
            self._directory(self.state_dir / "runs" / run_id, create=True)
            backup = {"schema_version": 1, "run_id": run_id, "created_ns": time.time_ns(),
                      "plan_sha256": plan_digest(report), "files": entries,
                      "nonfile_run": force_run,
                      "watched_files": watched, "watched_patterns": report.get("watched_patterns", {})}
            self._save(f"/runs/{run_id}/backup.json", backup)
            journal = {"run_id": run_id, "phase": "prepared", "attempted": [],
                       "backup_sha256": hashlib.sha256(encoded_json(backup)).hexdigest()}
            self._save(f"/runs/{run_id}/journal.json", journal)
            self._save("/active.json", {"run_id": run_id})
            return run_id

    def apply_files(self, run_id: str, *, refresh: Callable[[], dict[str, Any]],
                    before_apply: Callable[[], None] | None = None) -> None:
        """Internal primitive, not a public apply command or a network supervisor."""
        with self._lock():
            backup, journal = self._run(run_id)
            if self._active() != run_id or journal["phase"] != "prepared":
                raise TransactionError("Only the active prepared run can write files")
            if plan_digest(refresh()) != backup["plan_sha256"]:
                raise StalePlan("Prepared plan changed; recover this run and review a new plan")
            self._verify_watched(backup)
            if before_apply is not None:
                before_apply()
            journal["phase"] = "applying"
            self._save(f"/runs/{run_id}/journal.json", journal)
            try:
                for entry in backup["files"]:
                    # Write intent first: recovery handles a crash immediately before
                    # or after replace, without needing the writer to record success.
                    journal["attempted"].append(entry["path"])
                    self._save(f"/runs/{run_id}/journal.json", journal)
                    self.fs.replace(entry["path"], entry["after"], expected=fingerprint(entry["before"]))
                journal["phase"] = "applied"
                self._save(f"/runs/{run_id}/journal.json", journal)
            except BaseException as error:
                try:
                    self._recover(run_id)
                except (TransactionError, OSError) as recovery_error:
                    raise RecoveryError(f"File write failed; recovery needs attention: {recovery_error}") from error
                raise

    def _recover(self, run_id: str, *, coordinated: bool = False,
                 participant: Callable[[], None] | None = None) -> dict[str, Any]:
        backup, journal = self._run(run_id)
        if journal["phase"] in FINAL_PHASES:
            self._clear(run_id)
            return journal
        if journal.get("supervised") and not coordinated:
            raise RecoveryError("Supervised run: use recovery.py recover for combined file/network recovery")
        if self._active() != run_id:
            raise TransactionError("Recovery may restore only the active run")
        journal["phase"] = "rolling_back"
        self._save(f"/runs/{run_id}/journal.json", journal)
        failures = []
        entries = {entry["path"]: entry for entry in backup["files"]}
        for path in reversed(journal["attempted"]):
            entry = entries[path]
            try:
                current = self.fs.snapshot(path)
                if same_file(current, entry["before"]):
                    continue
                if not same_file(current, entry["after"]):
                    raise RecoveryError(f"{path}: external change; preserved for manual review")
                self.fs.replace(path, entry["before"], expected=fingerprint(current), restore_time=True)
            except (TransactionError, OSError) as error:
                failures.append(str(error))
        if participant is not None:
            try:
                participant()
            except (TransactionError, OSError) as error:
                failures.append(str(error))
        journal["phase"] = "recovery_failed" if failures else "rolled_back"
        journal["failures"] = failures
        self._save(f"/runs/{run_id}/journal.json", journal)
        if failures:
            raise RecoveryError("; ".join(failures))
        self._clear(run_id)
        return journal

    def recover(self, run_id: str) -> dict[str, Any]:
        """Idempotent manual recovery, usable by a separate process after writer death."""
        with self._lock():
            return self._recover(run_id)

    def commit(self, run_id: str) -> None:
        """Future supervisor calls only after its own health/connectivity checks."""
        with self._lock():
            self._commit_locked(run_id)

    def _commit_locked(self, run_id: str, *, coordinated: bool = False,
                       before_commit: Callable[[], None] | None = None) -> None:
        backup, journal = self._run(run_id)
        if journal.get("supervised") and not coordinated:
            raise TransactionError("Supervised run requires the recovery supervisor's health checks")
        if self._active() != run_id or journal["phase"] != "applied":
            raise TransactionError("Only the active applied run can commit")
        for entry in backup["files"]:
            if not same_file(self.fs.snapshot(entry["path"]), entry["after"]):
                raise StalePlan(f"{entry['path']}: candidate changed before commit")
        if before_commit is not None:
            before_commit()
        journal["phase"] = "committed"
        self._save(f"/runs/{run_id}/journal.json", journal)
        self._clear(run_id)

    def status(self, run_id: str) -> dict[str, Any]:
        with self._lock():
            _, journal = self._run(run_id)
            return copy.deepcopy(journal)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Inspect or manually recover an existing file transaction."
                                     " Does not restore live networking.")
    parser.add_argument("operation", choices=("status", "recover"))
    parser.add_argument("run_id", help="32-character ID of an existing run")
    options = parser.parse_args(argv)
    try:
        manager = FileTransaction()
        result = manager.recover(options.run_id) if options.operation == "recover" else manager.status(options.run_id)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (TransactionError, OSError) as error:
        print(f"Recovery: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
