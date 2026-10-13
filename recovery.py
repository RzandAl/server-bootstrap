"""Independent systemd recovery. Bootstrap's production apply remains disabled."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import ipaddress
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
bootstrap = sys.modules.get("bootstrap") or peer_module("bootstrap")
ssh = sys.modules.get("ssh_session") or peer_module("ssh_session")
probe = sys.modules.get("ipv6_probe") or peer_module("ipv6_probe")
host = sys.modules.get("preflight") or peer_module("preflight")
pkg = sys.modules.get("packages") or peer_module("packages")
base = sys.modules.get("base_apply") or peer_module("base_apply")
UNIT_DIRECTORY = Path("/etc/systemd/system")
SSH_BUNDLE = ("bootstrap.py", "transaction.py", "network_recovery.py", "ssh_session.py", "recovery.py")
PROBE_BUNDLE = (*SSH_BUNDLE, "ipv6_probe.py")
BUNDLE = (*PROBE_BUNDLE, "preflight.py", "packages.py", "base_apply.py")
LEGACY_BUNDLE = ("transaction.py", "network_recovery.py", "recovery.py")
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
                 unit_dir: Path = UNIT_DIRECTORY, backend_factory: Callable = net.IPBackend,
                 session_inspector: ssh.SSHInspector | None = None,
                 probe_backend_factory: Callable = probe.ProbeBackend,
                 probe_connector: probe.TCPConnector | None = None,
                 package_backend_factory: Callable = pkg.AptBackend,
                 hostname_backend_factory: Callable = base.HostnameBackend):
        self.manager = manager
        self.systemd = systemd or Systemd()
        self.unit_dir = Path(unit_dir).absolute()
        self.units_fs = tx.RootFS(self.unit_dir)
        self.backend_factory = backend_factory
        self.session_inspector = session_inspector or ssh.SSHInspector()
        self.probe_backend_factory, self.probe_connector = probe_backend_factory, probe_connector
        self.package_backend_factory, self.hostname_backend_factory = package_backend_factory, hostname_backend_factory

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
                or set(config["bundle_sha256"]) not in (set(BUNDLE), set(PROBE_BUNDLE), set(SSH_BUNDLE), set(LEGACY_BUNDLE))):
            raise tx.TransactionError("Invalid supervisor configuration")
        net.interface_name(config["interface"])
        expected_texts = unit_texts(run_id, self.manager.state_dir / "runs" / run_id / "worker/recovery.py",
                                   self.manager.state_dir, config["timeout"], config["deadline_ns"])
        if config.get("unit_texts") != expected_texts:
            raise tx.TransactionError("Recovery unit definitions do not match the saved run")
        if config.get("namespace") is not None and self.manager.fs.root == Path("/"):
            raise tx.TransactionError("Fixture namespaces are not allowed for the system root")
        if config.get("acknowledgment") is not None:
            self.validate_acknowledgment(config["acknowledgment"])
        if config.get("ipv6_probe") is not None and probe.validate_config(config["ipv6_probe"]) != config["ipv6_probe"]:
            raise tx.TransactionError("Noncanonical IPv6 probe configuration")
        if config.get("base_apply") is not None:
            base.validate_config(config["base_apply"])
            if config.get("acknowledgment") is None:
                raise tx.TransactionError("Base requires a fresh SSH acknowledgment contract")
        return config

    @staticmethod
    def validate_acknowledgment(value: dict[str, Any]) -> None:
        if (not isinstance(value, dict) or set(value) != {"account", "targets", "origin", "ready_ticks", "phase", "evidence"}
                or value.get("phase") not in ("pending", "waiting", "acknowledging", "acknowledged", "rolled_back")
                or not isinstance(value.get("targets"), list) or not 1 <= len(value["targets"]) <= 2
                or any(not isinstance(target, str) for target in value["targets"])
                or len(set(value["targets"])) != len(value["targets"])):
            raise tx.TransactionError("Invalid SSH acknowledgment contract")
        ssh.validate_account(value["account"])
        for target in value["targets"]:
            parsed = ipaddress.ip_address(ssh.address(target))
            if (str(parsed) != target or parsed.is_loopback or parsed.is_link_local
                    or parsed == ipaddress.IPv4Address("255.255.255.255")):
                raise tx.TransactionError("Invalid candidate SSH target")
        for evidence in (value["origin"], value["evidence"]):
            if evidence is not None:
                ssh.validate_evidence(evidence, value["account"])
        ready = value["ready_ticks"]
        if ready is not None and (type(ready) is not int or ready <= 0):
            raise tx.TransactionError("Invalid SSH acknowledgment ready time")
        if (value["phase"] in {"waiting", "acknowledging", "acknowledged"} and ready is None
                or value["phase"] in {"acknowledging", "acknowledged"} and value["evidence"] is None
                or value["phase"] in {"pending", "waiting"} and value["evidence"] is not None):
            raise tx.TransactionError("SSH acknowledgment evidence is inconsistent with its phase")

    def network(self, run_id: str, config: dict[str, Any]) -> net.NetworkJournal:
        backend = self.backend_factory(config["interface"], namespace=config.get("namespace"))
        return net.NetworkJournal(self.manager, run_id, backend)

    def ipv6_probe(self, run_id: str, config: dict[str, Any]) -> probe.IPv6Probe | None:
        if config.get("ipv6_probe") is None:
            return None
        backend = self.probe_backend_factory(config["interface"], namespace=config.get("namespace"))
        return probe.IPv6Probe(self.manager, run_id, backend, connector=self.probe_connector)

    def verify_probe(self, run_id: str, config: dict[str, Any]) -> None:
        participant = self.ipv6_probe(run_id, config)
        if participant is not None:
            if participant.load()["config"] != config["ipv6_probe"]:
                raise tx.TransactionError("IPv6 probe differs from its armed contract")
            participant.verify_passed_locked()

    def packages(self, run_id: str, config: dict) -> pkg.PackageJournal:
        backend = self.package_backend_factory(self.manager.fs.root, namespace=config.get("namespace"))
        return pkg.PackageJournal(self.manager, run_id, backend)

    def hostname(self, run_id: str) -> base.HostnameJournal:
        return base.HostnameJournal(self.manager, run_id, self.hostname_backend_factory(self.manager.fs.root))

    def check_guard(self, config: dict) -> None:
        if (self.systemd.generation() != config["generation"]
                or time.monotonic_ns() >= config["monotonic_deadline_ns"] or time.time_ns() >= config["deadline_ns"]
                or not self.systemd.active(config["units"]["timer"])):
            raise tx.RecoveryError("Independent recovery guard is absent or expired")

    def verify_base(self, run_id: str, config: dict) -> None:
        if config.get("base_apply") is None:
            return
        self.hostname(run_id).verify_locked()
        self.packages(run_id, config).verify_completed_locked()
        for entry in config["report"]["files"]:
            after = entry["after"]
            expected = (tx.regular(after["content"].encode(), after["mode"], after["uid"], after["gid"])
                        if after["kind"] == "regular" else {**after, "mode": 0o777})
            if not tx.same_file(self.manager.fs.snapshot(entry["path"]), expected):
                raise tx.TransactionError("Base file health changed before acknowledgment: " + entry["path"])

    def arm(self, run_id: str, report: dict[str, Any], *, interface: str,
            operations: list[dict[str, Any]], timeout: int = 300, namespace: str | None = None,
            ssh_targets: list[str] | None = None, ipv6_probe: dict | None = None,
            deferred_operations: list[dict] | None = None, base_apply: dict | None = None) -> None:
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
        if base_apply is not None:
            base.validate_config(base_apply)
            if (base_apply != report.get("base_apply") or ssh_targets is None
                    or base_apply["operations"] != operations or base_apply["deferred_operations"] != (deferred_operations or [])):
                raise tx.StalePlan("Base execution differs from its complete reviewed contract")
        elif report.get("base_apply") is not None:
            raise tx.TransactionError("A reviewed Base cannot be armed without its Base participants")
        ipv6_probe = probe.validate_config(ipv6_probe) if ipv6_probe is not None else None
        if report.get("ipv6_probe") is not None and report["ipv6_probe"] != ipv6_probe:
            raise tx.StalePlan("IPv6 probe differs from the reviewed host plan")
        acknowledgment = None
        if ssh_targets is not None:
            account = self.session_inspector.account()
            acknowledgment = {"account": account, "targets": ssh_targets,
                              "origin": self.session_inspector.capture(account, required=False),
                              "ready_ticks": None, "phase": "pending", "evidence": None}
            self.validate_acknowledgment(acknowledgment)
            if base_apply is not None:
                original = base_apply["ssh_origin"]
                armed = acknowledgment["origin"]
                if (base_apply["account"] != account or (original is None) != (armed is None)
                        or original is not None and not ssh.same_connection(original, armed)):
                    raise tx.StalePlan("Original SSH transport or invoking account changed after Base review")
            reviewed_account = report.get("facts", {}).get("account", {})
            if any(reviewed_account.get(key, account[key]) != account[key] for key in account):
                raise tx.StalePlan("Reviewed invoking account changed before SSH recovery arming")
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
                      "bundle_sha256": {}, "unit_texts": texts, "report": report,
                      "acknowledgment": acknowledgment, "ipv6_probe": ipv6_probe, "base_apply": base_apply}
            network = self.network(run_id, config)
            network.prepare_locked(operations, deferred_operations=deferred_operations)
            if base_apply is not None:
                if network.load()["before"] != base_apply["network_before"]:
                    raise tx.StalePlan("Base network changed before arming")
                self.packages(run_id, config).prepare_locked(base_apply["package_before"])
                self.hostname(run_id).prepare_locked(base_apply["hostname_before"], base_apply["profile"]["hostname"])
            if acknowledgment is not None or ipv6_probe is not None:
                projected = {net.identity(obj): obj for obj in network.load()["before"]["objects"]}
                for operation in network.load()["operations"]:
                    if operation["action"] == "add":
                        projected[net.identity(operation["object"])] = operation["object"]
                    else:
                        projected.pop(net.identity(operation["object"]), None)
                addresses = {obj["cidr"].split("/")[0] for obj in projected.values() if obj["kind"] == "address"}
                if acknowledgment is not None and not set(acknowledgment["targets"]) <= addresses:
                    raise tx.TransactionError("SSH acknowledgment targets are absent from the planned final addresses")
                if ipv6_probe is not None:
                    candidate = ipv6_probe["cidr"]
                    v6_addresses = {obj["cidr"] for obj in projected.values() if obj["kind"] == "address" and obj["family"] == 6}
                    additions = [entry["object"]["cidr"] for entry in network.load()["operations"]
                                 if entry["action"] == "add" and entry["object"]["kind"] == "address" and entry["object"]["family"] == 6]
                    defaults = [obj for obj in projected.values() if obj["kind"] == "route" and obj["family"] == 6 and obj["dst"] == "::/0"]
                    if (candidate not in v6_addresses or any(address != candidate for address in additions)
                            or len(defaults) != 1 or defaults[0].get("gateway") != ipv6_probe["gateway"]):
                        raise tx.TransactionError("IPv6 probe must match the planned permanent candidate and default gateway")
            participant = self.ipv6_probe(run_id, config)
            if participant is not None:
                participant.prepare_locked(ipv6_probe, network.load()["before"])
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
            if config.get("base_apply") is not None:
                if (self.packages(run_id, config).backend.inspect() != config["base_apply"]["package_before"]
                        or self.hostname(run_id).backend.snapshot() != config["base_apply"]["hostname_before"]):
                    raise tx.StalePlan("Reviewed Base runtime or package state changed before writes")
            participant = self.ipv6_probe(run_id, config)
            if participant is not None:
                if participant.load()["config"] != config["ipv6_probe"]:
                    raise tx.StalePlan("Prepared IPv6 probe differs from the reviewed contract")
                participant.run_locked()
                self.verify_probe(run_id, config)
        if (self.systemd.generation() != config["generation"]
                or time.monotonic_ns() >= config["monotonic_deadline_ns"]
                or time.time_ns() >= config["deadline_ns"]
                or not self.systemd.active(config["units"]["timer"])):
            raise tx.RecoveryError("Independent guard expired before permanent file application")
        self.manager.apply_files(run_id, refresh=lambda: config["report"])
        with self.manager._lock():
            self.network(run_id, config).apply_locked()
            if config.get("base_apply") is not None:
                self.check_guard(config)
                self.hostname(run_id).apply_locked()
                self.packages(run_id, config).run_locked(guard=lambda: self.check_guard(config))
                self.verify_base(run_id, config)
                self.check_guard(config)
            config = self.load(run_id)
            if config.get("acknowledgment") is not None:
                config["acknowledgment"]["ready_ticks"] = self.session_inspector.ticks()
                config["acknowledgment"]["phase"] = "waiting"
                self.manager._save(self.path(run_id), config)

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
            def recover_participants():
                failures = []
                participant = self.ipv6_probe(run_id, config)
                for restore in ([lambda: participant.cleanup_locked(boot=different_boot)] if participant is not None else []) + \
                               [lambda: network.recover_locked(boot=different_boot)] + \
                               ([lambda: self.hostname(run_id).recover_locked(boot=different_boot),
                                 lambda: self.packages(run_id, config).observe_retained_locked()]
                                if config.get("base_apply") is not None else []):
                    try:
                        restore()
                    except (tx.TransactionError, OSError, ValueError, subprocess.SubprocessError) as error:
                        failures.append(str(error))
                if failures:
                    raise tx.RecoveryError("; ".join(failures))
            try:
                journal = self.manager._recover(run_id, coordinated=True,
                                               participant=recover_participants)
            except (tx.TransactionError, OSError) as error:
                config["phase"] = "recovery_failed"
                config["failure"] = str(error)
                self.manager._save(self.path(run_id), config)
                raise
            config["phase"] = journal["phase"]
            acknowledgment = config.get("acknowledgment")
            if acknowledgment is not None:
                acknowledgment["phase"] = "acknowledged" if journal["phase"] == "committed" else "rolled_back"
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
            if config.get("acknowledgment") is not None:
                raise tx.TransactionError("This run requires fresh SSH acknowledgment; fixture commit cannot bypass it")
            if (self.systemd.generation() != config["generation"]
                    or time.monotonic_ns() >= config["monotonic_deadline_ns"]
                    or not self.systemd.active(config["units"]["timer"]) or verify() is not True):
                raise tx.TransactionError("Health check failed or rollback deadline expired")
            self.network(run_id, config).verify_applied_locked()
            self.verify_probe(run_id, config)
            self.network(run_id, config).finalize_locked()
            self.manager._commit_locked(run_id, coordinated=True)
            config["phase"] = "committed"
            self.manager._save(self.path(run_id), config)
            self.cleanup(run_id, config)

    def acknowledgment_guard(self, run_id: str, config: dict[str, Any]) -> dict:
        if (self.systemd.generation() != config["generation"]
                or time.monotonic_ns() >= config["monotonic_deadline_ns"]
                or time.time_ns() >= config["deadline_ns"]
                or not self.systemd.active(config["units"]["timer"])):
            raise tx.TransactionError("SSH acknowledgment expired or its independent guard is absent")
        account = self.session_inspector.account()
        acknowledgment = config["acknowledgment"]
        if account != acknowledgment["account"]:
            raise tx.TransactionError("Only the original invoking account may acknowledge this run")
        evidence = self.session_inspector.capture(account)
        ssh.validate_evidence(evidence, account)
        if evidence["monitor_start_ticks"] <= acknowledgment["ready_ticks"]:
            raise tx.TransactionError("Reconnect with a new SSH connection opened after application completed")
        if acknowledgment["origin"] is not None and ssh.same_connection(evidence, acknowledgment["origin"]):
            raise tx.TransactionError("The original SSH connection cannot acknowledge its own transition")
        if evidence["connection"]["server_address"] not in acknowledgment["targets"]:
            raise tx.TransactionError("SSH acknowledgment must connect to a planned candidate address")
        if time.monotonic_ns() >= config["monotonic_deadline_ns"] or time.time_ns() >= config["deadline_ns"]:
            raise tx.TransactionError("SSH acknowledgment deadline expired while collecting evidence")
        return evidence

    def acknowledge(self, run_id: str) -> dict[str, Any]:
        """Verify a new authenticated connection and the complete fixture result."""
        if self.manager.fs.root == Path("/"):
            raise tx.TransactionError("Production Base acknowledgment awaits module/probe wiring")
        with self.manager._lock():
            config = self.load(run_id)
            acknowledgment = config.get("acknowledgment")
            if acknowledgment is None:
                raise tx.TransactionError("Run has no fresh SSH acknowledgment contract")
            _, journal = self.manager._run(run_id)
            if journal["phase"] == "committed" and acknowledgment["phase"] in {"acknowledging", "acknowledged"}:
                acknowledgment["phase"] = "acknowledged"
                self.manager._save(self.path(run_id), config)
                self.cleanup(run_id, config)
                return journal
            if (self.manager._active() != run_id or journal["phase"] != "applied"
                    or config["phase"] != "started" or acknowledgment["phase"] not in {"waiting", "acknowledging"}):
                raise tx.TransactionError("Only the active completed transition can await SSH acknowledgment")
            self.verify_bundle(run_id, config)
            evidence = self.acknowledgment_guard(run_id, config)
            self.verify_probe(run_id, config)
            self.verify_base(run_id, config)
            self.network(run_id, config).verify_applied_locked()
            acknowledgment["phase"], acknowledgment["evidence"] = "acknowledging", evidence
            self.manager._save(self.path(run_id), config)
            # Fresh transport is proven before removing the old addresses/path.
            self.network(run_id, config).finalize_locked()
            def final_guard():
                self.verify_probe(run_id, config)
                self.verify_base(run_id, config)
                self.network(run_id, config).verify_applied_locked()
                if self.acknowledgment_guard(run_id, config) != evidence:
                    raise tx.TransactionError("SSH connection changed before terminal commit")
            self.manager._commit_locked(run_id, coordinated=True, before_commit=final_guard)
            config["phase"], acknowledgment["phase"] = "committed", "acknowledged"
            self.manager._save(self.path(run_id), config)
            self.cleanup(run_id, config)
            return self.manager._run(run_id)[1]


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
    parser.add_argument("operation", choices=("status", "recover", "acknowledge", "_apply", "_boot"))
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
        elif options.operation == "acknowledge":
            print(json.dumps(supervisor.acknowledge(options.run_id), indent=2))
        else:
            print(json.dumps(manager.status(options.run_id), indent=2))
        return 0
    except (tx.TransactionError, OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"Recovery: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
