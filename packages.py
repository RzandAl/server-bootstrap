"""Bounded apt execution and diagnostics. Installed packages are never rolled back."""

from __future__ import annotations

from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from typing import Any

import transaction as tx
import network_recovery as net

bootstrap = sys.modules.get("bootstrap")
if bootstrap is None:
    raise RuntimeError("Package operations require the trusted recovery loader")

APT_TIMEOUT = 240
QUERY_TIMEOUT = 12
OUTPUT_LIMIT = 1024 * 1024
LOG_TAIL = 16000
PACKAGE = re.compile(r"[a-z0-9][a-z0-9+.-]*(?::[a-z0-9][a-z0-9-]*)?\Z")
PHASES = {"prepared", "running", "completed", "failed", "retained"}


def inventory(output: str, audit: str) -> dict:
    packages = {}
    if len(output) > OUTPUT_LIMIT or len(audit) > OUTPUT_LIMIT:
        raise tx.TransactionError("Package inventory exceeds its read limit")
    for line in output.splitlines():
        fields = line.split("\t")
        if len(fields) != 3:
            raise tx.TransactionError("Malformed package inventory")
        name, version, state = fields
        if (not PACKAGE.fullmatch(name) or name in packages or len(version) > 256
                or version and not re.fullmatch(r"[A-Za-z0-9.+:~_-]+", version)
                or not re.fullmatch(r"[uirphn][ncHUFWti][ R]", state)):
            raise tx.TransactionError("Invalid package identity/version/state")
        packages[name] = {"version": version, "state": state}
    healthy = not audit.strip() and all(item["state"][1] in "nci" and item["state"][2] == " " for item in packages.values())
    return {"packages": dict(sorted(packages.items())), "audit": audit, "healthy": healthy}


def validate_snapshot(value: Any) -> dict:
    if not isinstance(value, dict) or set(value) != {"packages", "audit", "healthy"} or type(value["healthy"]) is not bool:
        raise tx.TransactionError("Invalid package snapshot")
    if not isinstance(value["packages"], dict) or not isinstance(value["audit"], str):
        raise tx.TransactionError("Invalid package snapshot data")
    lines = []
    for name, item in value["packages"].items():
        if not isinstance(item, dict) or set(item) != {"version", "state"} or not all(isinstance(item[k], str) for k in item):
            raise tx.TransactionError("Invalid package record")
        lines.append(f"{name}\t{item['version']}\t{item['state']}")
    canonical = inventory("\n".join(lines), value["audit"])
    if canonical != value:
        raise tx.TransactionError("Noncanonical package snapshot")
    return value


def installed(value: dict) -> set[str]:
    return {name.split(":")[0] for name, item in value["packages"].items() if item["state"][1:] == "i "}


def missing(value: dict) -> list[str]:
    return sorted(set(bootstrap.BASE_PACKAGES) - installed(value))


class AptBackend:
    def __init__(self, root: Path, *, namespace: str | None = None):
        self.root = Path(root).absolute()
        if namespace is not None and not net.NAMESPACE.fullmatch(namespace):
            raise tx.TransactionError("Invalid package fixture namespace")
        if self.root == Path("/") and namespace is not None:
            raise tx.TransactionError("A fixture namespace cannot target system packages")
        self.namespace = namespace

    def prefix(self, *, network: bool = False) -> list[str]:
        arguments = []
        if self.root != Path("/"):
            info = self.root.lstat()
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022
                    or self.root.resolve() != self.root):
                raise tx.TransactionError("APT fixture root must be a protected real directory")
            executable = shutil.which("chroot", path=net.SYSTEM_PATH)
            if executable is None:
                raise tx.TransactionError("chroot is required for isolated package checks")
            arguments = [executable, str(self.root)]
        if network and self.namespace is not None:
            executable = shutil.which("ip", path=net.SYSTEM_PATH)
            if executable is None:
                raise tx.TransactionError("iproute2 is required for isolated package networking")
            arguments = [executable, "netns", "exec", self.namespace, *arguments]
        return arguments

    def command(self, arguments: list[str], *, mutation: bool = False) -> dict:
        if mutation and self.root == Path("/"):
            raise tx.TransactionError("Production package application is not enabled")
        executable = shutil.which(arguments[0], path=net.SYSTEM_PATH)
        if executable is None:
            raise tx.TransactionError("Missing package command: " + arguments[0])
        prefix = self.prefix(network=mutation)
        # Query executables are fixed; a chroot uses its corresponding absolute
        # system binary. No profile controls command text, environment or paths.
        argv = [*prefix, executable, *arguments[1:]]
        with tempfile.TemporaryFile() as output:
            result = subprocess.run(argv, stdout=output, stderr=subprocess.STDOUT,
                                    timeout=APT_TIMEOUT if mutation else QUERY_TIMEOUT, check=False,
                                    env={"PATH": net.SYSTEM_PATH, "LC_ALL": "C", "DEBIAN_FRONTEND": "noninteractive"})
            size = output.tell()
            if not mutation and size > OUTPUT_LIMIT:
                raise tx.TransactionError("Package query exceeds its read limit")
            output.seek(max(0, size - LOG_TAIL) if mutation else 0)
            text = output.read().decode("utf-8", errors="replace")
        return {"returncode": result.returncode, "output": text, "truncated": mutation and size > LOG_TAIL}

    def inspect(self) -> dict:
        query = self.command(["dpkg-query", "-W", "-f=${binary:Package}\t${Version}\t${db:Status-Abbrev}\n"])
        audit = self.command(["dpkg", "--audit"])
        if query["returncode"] or audit["returncode"]:
            raise tx.TransactionError("Cannot inspect package state")
        return inventory(query["output"], audit["output"])

    def run(self, operation: str, names: list[str]) -> dict:
        if (not isinstance(names, list) or names != sorted(set(names))
                or not set(names) <= set(bootstrap.BASE_PACKAGES)):
            raise tx.TransactionError("Invalid selected package list")
        if operation == "update" and not names:
            arguments = list(bootstrap.APT_UPDATE)
        elif operation == "install" and names:
            arguments = [*bootstrap.APT_INSTALL, *names]
        else:
            raise tx.TransactionError("Invalid package operation")
        return self.command(arguments, mutation=True)


class PackageJournal:
    def __init__(self, manager: tx.FileTransaction, run_id: str, backend: AptBackend):
        manager._run_id(run_id)
        self.manager, self.run_id, self.backend = manager, run_id, backend
        self.path = f"/runs/{run_id}/packages.json"

    def prepare_locked(self, before: dict) -> None:
        validate_snapshot(before)
        if not before["healthy"] or self.backend.inspect() != before:
            raise tx.StalePlan("Package state is unhealthy or changed before arming")
        if self.manager.store.snapshot(self.path)["kind"] != "absent":
            raise tx.TransactionError("Package journal already exists")
        self.manager._save(self.path, {"schema_version": 1, "run_id": self.run_id, "phase": "prepared", "before": before,
                           "missing": missing(before), "steps": {"update": "pending", "install": "pending"},
                           "results": {}, "after": None, "manual_attention": False})

    def load(self) -> dict:
        value = self.manager._load(self.path)
        if (value.get("schema_version") != 1 or value.get("run_id") != self.run_id or value.get("phase") not in PHASES
                or value.get("missing") != missing(validate_snapshot(value.get("before")))
                or not isinstance(value.get("steps"), dict) or set(value["steps"]) != {"update", "install"}
                or any(v not in {"pending", "intent", "done", "skipped", "failed"} for v in value["steps"].values())
                or not isinstance(value.get("results"), dict) or type(value.get("manual_attention")) is not bool):
            raise tx.TransactionError("Invalid package journal")
        if value.get("after") is not None:
            validate_snapshot(value["after"])
        return value

    def run_locked(self, *, guard) -> None:
        value = self.load()
        if value["phase"] != "prepared" or self.backend.inspect() != value["before"]:
            raise tx.StalePlan("Package state changed before execution")
        value["phase"] = "running"
        self.manager._save(self.path, value)
        try:
            for operation, names in (("update", []), ("install", value["missing"])):
                guard()
                if operation == "install" and not names:
                    value["steps"][operation] = "skipped"
                    self.manager._save(self.path, value)
                    continue
                value["steps"][operation] = "intent"
                self.manager._save(self.path, value)
                result = self.backend.run(operation, names)
                value["results"][operation] = result
                if type(result.get("returncode")) is not int or result["returncode"] != 0:
                    value["steps"][operation] = "failed"
                    raise tx.RecoveryError(f"apt-get {operation} failed; details are retained in the private package journal")
                value["steps"][operation] = "done"
                self.manager._save(self.path, value)
            guard()
            value["after"] = self.backend.inspect()
            if not value["after"]["healthy"] or missing(value["after"]):
                raise tx.RecoveryError("APT completed without a healthy complete Base package set")
            value["phase"] = "completed"
            self.manager._save(self.path, value)
        except (tx.TransactionError, OSError, ValueError, subprocess.SubprocessError) as error:
            value["phase"], value["error"] = "failed", str(error)
            self.manager._save(self.path, value)
            raise

    def observe_retained_locked(self) -> None:
        """Read-only diagnosis after writer stop. Never repair, remove or downgrade."""
        value = self.load()
        try:
            value["after"] = self.backend.inspect()
            value["manual_attention"] = not value["after"]["healthy"]
            value.pop("inspection_error", None)
        except (tx.TransactionError, OSError, ValueError, subprocess.SubprocessError) as error:
            value["manual_attention"], value["inspection_error"] = True, str(error)
        value["phase"] = "retained"
        self.manager._save(self.path, value)

    def verify_completed_locked(self) -> None:
        value = self.load()
        if (value["phase"] != "completed" or value["steps"]["update"] != "done"
                or value["steps"]["install"] not in {"done", "skipped"}):
            raise tx.TransactionError("Base package steps have not completed")
        current = self.backend.inspect()
        if not current["healthy"] or missing(current):
            raise tx.TransactionError("Base package health changed before acknowledgment")
