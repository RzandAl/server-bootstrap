"""Independent systemd recovery. Bootstrap's production apply remains disabled."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
from typing import Any, Callable


def peer_module(name: str):
    """Load only explicit sibling files, including under python -I; no PATH imports."""
    path = Path(__file__).absolute().with_name(name + ".py")
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Missing recovery module: {name}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


tx = sys.modules.get("transaction") or peer_module("transaction")
net = sys.modules.get("network_recovery") or peer_module("network_recovery")
UNIT_DIRECTORY = Path("/etc/systemd/system")
BUNDLE = ("transaction.py", "network_recovery.py", "recovery.py")
SAFE_UNIT_PATH = re.compile(r"/[A-Za-z0-9_./-]+\Z")


def unit_names(run_id: str) -> dict[str, str]:
    tx.FileTransaction._run_id(run_id)
    prefix = "rzandal-bootstrap-" + run_id
    return {"apply": prefix + "-apply.service", "rollback": prefix + "-rollback.service",
            "timer": prefix + "-rollback.timer", "boot": prefix + "-boot.service"}


def unit_texts(run_id: str, worker: Path, state_dir: Path, timeout: int, deadline_ns: int) -> dict[str, str]:
    for path in (worker, state_dir):
        if not SAFE_UNIT_PATH.fullmatch(str(path)):
            raise tx.TransactionError("Recovery paths must not contain systemd expansions or quoting characters")
        tx.safe_path(str(path))
    if type(timeout) is not int or not 5 <= timeout <= 1800:
        raise tx.TransactionError("Recovery timeout must be between 5 and 1800 seconds")
    units = unit_names(run_id)
    command = f"/usr/bin/python3 -I {worker}"
    common = ("[Service]\nType=oneshot\nUser=root\nUMask=0077\nNoNewPrivileges=yes\n"
              "WorkingDirectory=/\nEnvironment=PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C\n"
              "StandardOutput=journal\nStandardError=journal\nTimeoutStopSec=3s\nKillMode=control-group\n")
    calendar = datetime.fromtimestamp((deadline_ns + 999_999_999) // 1_000_000_000, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    return {
        units["apply"]: f"[Unit]\nDescription=RzandAl supervised file/network worker {run_id}\nOnFailure={units['rollback']}\nStartLimitIntervalSec=0\n\n"
                        + common + f"TimeoutStartSec={timeout + 5}s\nExecStart={command} _apply {run_id}\n",
        units["rollback"]: f"[Unit]\nDescription=RzandAl independent rollback {run_id}\nStartLimitIntervalSec=0\n\n"
                           + common + f"TimeoutStartSec=90s\nRestart=on-failure\nRestartSec=5s\nExecStart={command} recover {run_id}\n",
        units["timer"]: f"[Unit]\nDescription=RzandAl rollback deadline {run_id}\n\n[Timer]\nOnActiveSec={timeout}s\nOnCalendar={calendar}\n"
                        f"AccuracySec=1s\nRandomizedDelaySec=0\nPersistent=yes\nUnit={units['rollback']}\n\n[Install]\nWantedBy=timers.target\n",
        units["boot"]: f"[Unit]\nDescription=RzandAl restore original files before networking {run_id}\nDefaultDependencies=no\n"
                       f"After=local-fs.target\nBefore=sysinit.target network-pre.target networking.service systemd-networkd.service NetworkManager.service\n"
                       f"RequiresMountsFor={state_dir}\nStartLimitIntervalSec=0\n\n" + common
                       + f"TimeoutStartSec=90s\nExecStart={command} _boot {run_id}\n\n[Install]\nWantedBy=sysinit.target\n"}


class Systemd:
    def ready(self) -> None:
        if not Path("/run/systemd/private").is_socket() or not Path("/run/dbus/system_bus_socket").is_socket():
            raise tx.TransactionError("Independent recovery requires systemd and a working system D-Bus socket")

    def command(self, *arguments: str, allow_missing: bool = False) -> str:
        executable = shutil.which("systemctl", path=net.SYSTEM_PATH)
        if executable is None:
            raise tx.TransactionError("systemctl is required for independent recovery")
        result = subprocess.run([executable, *arguments], capture_output=True, text=True,
                                timeout=12, check=False, env={"PATH": net.SYSTEM_PATH, "LC_ALL": "C"})
        missing = any(message in result.stderr.lower() for message in ("not loaded", "not found", "does not exist"))
        if result.returncode and not (allow_missing and missing):
            raise tx.RecoveryError("systemctl failed: " + result.stderr.strip())
        return result.stdout

    def generation(self) -> str:
        boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        started = self.command("show", "--property=UserspaceTimestampMonotonic", "--value").strip()
        if not re.fullmatch(r"[0-9a-f-]{36}", boot_id) or not started.isdecimal() or int(started) == 0:
            raise tx.TransactionError("Cannot establish the system manager's boot generation")
        return boot_id + ":" + started

    def active(self, unit: str) -> bool:
        return self.command("show", "--property=ActiveState", "--value", unit).strip() == "active"


class RecoverySupervisor:
    """Trusted internal API. There is no CLI arm/apply or production Base switch."""

    def __init__(self, manager: tx.FileTransaction, *, systemd: Systemd | None = None,
                 unit_dir: Path = UNIT_DIRECTORY, backend_factory: Callable = net.IPBackend):
        self.manager = manager
        self.systemd = systemd or Systemd()
        self.unit_dir = Path(unit_dir).absolute()
        self.units_fs = tx.RootFS(self.unit_dir)
        self.backend_factory = backend_factory

    def path(self, run_id: str) -> str:
        self.manager._run_id(run_id)
        return f"/runs/{run_id}/supervisor.json"

    def load(self, run_id: str) -> dict[str, Any]:
        config = self.manager._load(self.path(run_id))
        if (config.get("schema_version") != 1 or config.get("run_id") != run_id
                or config.get("root") != str(self.manager.fs.root)
                or config.get("state_dir") != str(self.manager.state_dir)
                or config.get("unit_dir") != str(self.unit_dir)
                or not isinstance(config.get("phase"), str) or config["phase"] not in {"arming", "armed", "started", "recovery_failed", "rolled_back", "committed"}
                or type(config.get("timeout")) is not int or not 5 <= config["timeout"] <= 1800
                or type(config.get("deadline_ns")) is not int or type(config.get("monotonic_deadline_ns")) is not int
                or config.get("units") != unit_names(run_id) or not isinstance(config.get("bundle_sha256"), dict)
                or set(config["bundle_sha256"]) != set(BUNDLE)):
            raise tx.TransactionError("Invalid supervisor configuration")
        net.interface_name(config["interface"])
        expected_texts = unit_texts(run_id, self.manager.state_dir / "runs" / run_id / "worker/recovery.py",
                                   self.manager.state_dir, config["timeout"], config["deadline_ns"])
        if config.get("unit_texts") != expected_texts:
            raise tx.TransactionError("Recovery unit definitions do not match the saved run")
        if config.get("namespace") is not None and self.manager.fs.root == Path("/"):
            raise tx.TransactionError("Fixture namespaces are not allowed for the system root")
        return config

    def network(self, run_id: str, config: dict[str, Any]) -> net.NetworkJournal:
        backend = self.backend_factory(config["interface"], namespace=config.get("namespace"))
        return net.NetworkJournal(self.manager, run_id, backend)

    def arm(self, run_id: str, report: dict[str, Any], *, interface: str,
            operations: list[dict[str, Any]], timeout: int = 300, namespace: str | None = None) -> None:
        if self.manager.owner != 0 and self.manager.fs.root == Path("/"):
            raise tx.TransactionError("System recovery requires root")
        if namespace is not None and self.manager.fs.root == Path("/"):
            raise tx.TransactionError("Namespaces are for isolated fixtures only")
        worker_dir = self.manager.state_dir / "runs" / run_id / "worker"
        worker = worker_dir / "recovery.py"
        deadline = time.time_ns() + timeout * 1_000_000_000
        texts = unit_texts(run_id, worker, self.manager.state_dir, timeout, deadline)
        self.systemd.ready()
        generation = self.systemd.generation()
        with self.manager._lock():
            backup, journal = self.manager._run(run_id)
            if (self.manager._active() != run_id or journal["phase"] != "prepared"
                    or journal.get("supervised") or tx.plan_digest(report) != backup["plan_sha256"]):
                raise tx.TransactionError("Only the active reviewed prepared run can be armed")
            self.manager._verify_watched(backup)
            for name in texts:
                if self.units_fs.snapshot("/" + name)["kind"] != "absent":
                    raise tx.TransactionError("Recovery unit name is already owned; refusing to overwrite it")
            config = {"schema_version": 1, "run_id": run_id, "root": str(self.manager.fs.root),
                      "state_dir": str(self.manager.state_dir), "unit_dir": str(self.unit_dir),
                      "interface": interface, "namespace": namespace, "timeout": timeout,
                      "deadline_ns": deadline, "monotonic_deadline_ns": time.monotonic_ns() + timeout * 1_000_000_000,
                      "generation": generation, "phase": "arming", "units": unit_names(run_id),
                      "bundle_sha256": {}, "unit_texts": texts, "report": report}
            network = self.network(run_id, config)
            network.prepare_locked(operations)
            self.manager._directory(worker_dir, create=True)
            for name in BUNDLE:
                data = Path(__file__).absolute().with_name(name).read_bytes()
                path = f"/runs/{run_id}/worker/{name}"
                if self.manager.store.snapshot(path)["kind"] != "absent":
                    raise tx.TransactionError("Worker bundle already exists")
                self.manager.store.replace(path, tx.regular(data, 0o600, self.manager.owner, self.manager.group),
                                           expected=tx.fingerprint({"kind": "absent"}))
                config["bundle_sha256"][name] = hashlib.sha256(data).hexdigest()
            self.manager._save(self.path(run_id), config)
            journal["supervised"] = True
            self.manager._save(f"/runs/{run_id}/journal.json", journal)
            for name, text in texts.items():
                self.units_fs.replace("/" + name, tx.regular(text.encode(), 0o644, self.manager.owner, self.manager.group),
                                      expected=tx.fingerprint({"kind": "absent"}))
        # No target mutation is permitted until enable/start AND active check succeed.
        self.systemd.command("daemon-reload")
        self.systemd.command("enable", config["units"]["boot"])
        self.systemd.command("enable", "--now", config["units"]["timer"])
        if not self.systemd.active(config["units"]["timer"]):
            raise tx.RecoveryError("Independent rollback timer did not become active")
        with self.manager._lock():
            config = self.load(run_id)
            _, journal = self.manager._run(run_id)
            if journal["phase"] != "prepared" or self.manager._active() != run_id:
                raise tx.RecoveryError("Run recovered while its timer was being armed")
            config["phase"] = "armed"
            self.manager._save(self.path(run_id), config)

    def verify_bundle(self, run_id: str, config: dict[str, Any]) -> None:
        self.manager._directory(self.manager.state_dir / "runs" / run_id / "worker", create=False)
        for name, digest in config["bundle_sha256"].items():
            state = self.manager.store.snapshot(f"/runs/{run_id}/worker/{name}")
            self.manager._private(state)
            if state["sha256"] != digest:
                raise tx.TransactionError("Protected worker checksum mismatch")

    def start(self, run_id: str) -> None:
        config = self.load(run_id)
        if self.manager.fs.root == Path("/"):
            raise tx.TransactionError("Production Base apply is not enabled")
        if config["phase"] != "armed" or not self.systemd.active(config["units"]["timer"]):
            raise tx.TransactionError("Independent recovery must be active before writes")
        self.verify_bundle(run_id, config)
        with self.manager._lock():
            config = self.load(run_id)
            _, journal = self.manager._run(run_id)
            if (journal["phase"] != "prepared" or self.manager._active() != run_id
                    or self.systemd.generation() != config["generation"]
                    or time.monotonic_ns() >= config["monotonic_deadline_ns"]):
                raise tx.RecoveryError("Run expired or recovered before its worker could start")
            config["phase"] = "started"
            self.manager._save(self.path(run_id), config)
        self.systemd.command("start", "--no-block", config["units"]["apply"])

    def apply_fixture(self, run_id: str) -> None:
        config = self.load(run_id)
        if self.manager.fs.root == Path("/") or config["phase"] != "started":
            raise tx.TransactionError("Worker application is enabled only for isolated fixture roots")
        self.verify_bundle(run_id, config)
        if (self.systemd.generation() != config["generation"]
                or not self.systemd.active(config["units"]["timer"])
                or time.monotonic_ns() >= config["monotonic_deadline_ns"]):
            raise tx.RecoveryError("Recovery guard is absent, expired, or belongs to another boot")
        with self.manager._lock():
            network = self.network(run_id, config)
            if network.backend.snapshot() != network.load()["before"]:
                raise tx.StalePlan("Live network changed before worker application")
        self.manager.apply_files(run_id, refresh=lambda: config["report"])
        with self.manager._lock():
            self.network(run_id, config).apply_locked()

    def cleanup(self, run_id: str, config: dict[str, Any], *, clean_stamp: bool = True) -> None:
        # Stop/disable only names generated for this run. Do not stop this recovery
        # service from inside itself; it exits normally after cleanup.
        self.systemd.command("disable", "--now", config["units"]["timer"], allow_missing=True)
        self.systemd.command("disable", config["units"]["boot"], allow_missing=True)
        if clean_stamp:
            self.systemd.command("clean", "--what=state", config["units"]["timer"], allow_missing=True)
        for name, text in config["unit_texts"].items():
            current = self.units_fs.snapshot("/" + name)
            if current["kind"] == "absent":
                continue
            expected = tx.regular(text.encode(), 0o644, self.manager.owner, self.manager.group)
            if not tx.same_file(current, expected):
                raise tx.RecoveryError("External recovery-unit edit preserved for manual review")
            self.units_fs.replace("/" + name, {"kind": "absent"}, expected=tx.fingerprint(current))
        self.systemd.command("daemon-reload")

    def recover(self, run_id: str, *, boot: bool = False) -> dict[str, Any]:
        config = self.load(run_id)
        different_boot = self.systemd.generation() != config["generation"]
        if boot and not different_boot:
            raise tx.TransactionError("Boot recovery may not discard a current boot's network journal")
        self.systemd.command("stop", config["units"]["apply"], allow_missing=True)
        with self.manager._lock():
            config = self.load(run_id)
            # Both restorations run even if one fails. The active pointer is cleared
            # only after both succeed, or after observing a committed terminal run.
            network = self.network(run_id, config)
            try:
                journal = self.manager._recover(run_id, coordinated=True,
                                               participant=lambda: network.recover_locked(boot=different_boot))
            except (tx.TransactionError, OSError) as error:
                config["phase"] = "recovery_failed"
                config["failure"] = str(error)
                self.manager._save(self.path(run_id), config)
                raise
            config["phase"] = journal["phase"]
            self.manager._save(self.path(run_id), config)
            # Early boot precedes the system bus. Disable units and restore files
            # using the manager's private socket; retain the harmless timer stamp.
            self.cleanup(run_id, config, clean_stamp=not different_boot)
        return journal

    def commit_fixture(self, run_id: str, *, verify: Callable[[], bool]) -> None:
        """Test lifecycle only. Fresh-SSH acknowledgment for real Base is pending."""
        if self.manager.fs.root == Path("/"):
            raise tx.TransactionError("Production acknowledgment is not implemented")
        with self.manager._lock():
            config = self.load(run_id)
            if (self.systemd.generation() != config["generation"]
                    or time.monotonic_ns() >= config["monotonic_deadline_ns"]
                    or not self.systemd.active(config["units"]["timer"]) or verify() is not True):
                raise tx.TransactionError("Health check failed or rollback deadline expired")
            self.network(run_id, config).verify_applied_locked()
            self.manager._commit_locked(run_id, coordinated=True)
            config["phase"] = "committed"
            self.manager._save(self.path(run_id), config)
            self.cleanup(run_id, config)


def cli_manager(run_id: str) -> tx.FileTransaction:
    tx.FileTransaction._run_id(run_id)
    script = Path(__file__).absolute()
    deployed = script.parent.name == "worker" and script.parent.parent.name == run_id and script.parent.parent.parent.name == "runs"
    state_dir = script.parent.parent.parent.parent if deployed else tx.STATE_DIRECTORY
    manager = tx.FileTransaction(state_dir=state_dir)
    # The state directory and run are private before trusting their saved root.
    with manager._lock():
        manager._run(run_id)
        config = manager._load(f"/runs/{run_id}/supervisor.json")
        root = config.get("root")
        if not isinstance(root, str) or (root != "/" and not SAFE_UNIT_PATH.fullmatch(root)):
            raise tx.TransactionError("Invalid saved target root")
        if root != "/":
            tx.safe_path(root)
    return tx.FileTransaction(root=Path(root), state_dir=state_dir)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Inspect or recover a supervised run; production Base apply is unavailable.")
    parser.add_argument("operation", choices=("status", "recover", "_apply", "_boot"))
    parser.add_argument("run_id")
    options = parser.parse_args(argv)
    try:
        if os.geteuid() != 0:
            raise tx.TransactionError("Supervised system recovery requires root")
        manager = cli_manager(options.run_id)
        supervisor = RecoverySupervisor(manager)
        if options.operation in {"_apply", "_boot"}:
            if Path(__file__).absolute() != manager.state_dir / "runs" / options.run_id / "worker/recovery.py":
                raise tx.TransactionError("Internal worker operations require the protected installed bundle")
            supervisor.verify_bundle(options.run_id, supervisor.load(options.run_id))
        if options.operation == "_apply":
            supervisor.apply_fixture(options.run_id)
        elif options.operation in {"recover", "_boot"}:
            print(json.dumps(supervisor.recover(options.run_id, boot=options.operation == "_boot"), indent=2))
        else:
            print(json.dumps(manager.status(options.run_id), indent=2))
        return 0
    except (tx.TransactionError, OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"Recovery: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
