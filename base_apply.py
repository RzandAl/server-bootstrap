"""Reviewed Base fixture lifecycle; production bootstrap remains gated."""

from __future__ import annotations

import copy
import ipaddress
import json
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys

import transaction as tx
import network_recovery as net
import packages as pkg
import ssh_session as ssh

bootstrap = sys.modules.get("bootstrap")
if bootstrap is None:
    raise RuntimeError("Base application requires the trusted recovery loader")

HOSTNAME_CODE = r'''
import json, socket, sys
p = json.loads(sys.argv[1])
if p["action"] == "set":
    socket.sethostname(p["hostname"].encode("ascii"))
print(json.dumps({"hostname": socket.gethostname()}))
'''
HOST_PHASES = {"prepared", "intent", "done", "reused", "rolled_back", "recovery_failed", "expired_on_boot"}


class HostnameBackend:
    def __init__(self, root: Path):
        self.root = Path(root).absolute()
        self.namespace = None if self.root == Path("/") else self.root.parent / "fixture-uts.ns"

    def identity(self) -> dict | None:
        if self.namespace is None:
            return None
        for parent in (self.namespace.parent, self.root):
            info = parent.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or parent.resolve() != parent:
                raise tx.TransactionError("Fixture hostname namespace parent is not protected")
        info = self.namespace.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise tx.TransactionError("Fixture hostname namespace is not a protected handle")
        return {"device": info.st_dev, "inode": info.st_ino}

    def command(self, action: str, hostname: str | None = None) -> str:
        if action not in {"get", "set"}:
            raise tx.TransactionError("Invalid hostname operation")
        self.identity()
        payload = json.dumps({"action": action, "hostname": hostname})
        arguments = ["/usr/bin/python3", "-I", "-c", HOSTNAME_CODE, payload]
        if self.namespace is not None:
            executable = shutil.which("nsenter", path=net.SYSTEM_PATH)
            if executable is None:
                raise tx.TransactionError("nsenter is required for a fixture hostname")
            arguments = [executable, "--uts=" + str(self.namespace), *arguments]
        elif action == "set":
            raise tx.TransactionError("Production runtime hostname application is not enabled")
        result = subprocess.run(arguments, capture_output=True, text=True, timeout=10, check=False,
                                env={"PATH": net.SYSTEM_PATH, "LC_ALL": "C"})
        if result.returncode or len(result.stdout) > 1024:
            raise tx.RecoveryError("Runtime hostname command failed")
        value = json.loads(result.stdout)
        if (not isinstance(value, dict) or set(value) != {"hostname"} or not isinstance(value["hostname"], str)
                or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", value["hostname"])):
            raise tx.TransactionError("Invalid runtime hostname inventory")
        return value["hostname"]

    def snapshot(self) -> dict:
        return {"hostname": self.command("get"), "namespace": self.identity()}

    def set(self, hostname: str) -> None:
        if not isinstance(hostname, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", hostname):
            raise tx.TransactionError("Invalid runtime hostname")
        if self.command("set", hostname) != hostname:
            raise tx.RecoveryError("Runtime hostname did not reach its recorded value")


class HostnameJournal:
    def __init__(self, manager: tx.FileTransaction, run_id: str, backend: HostnameBackend):
        manager._run_id(run_id)
        self.manager, self.run_id, self.backend = manager, run_id, backend
        self.path = f"/runs/{run_id}/hostname.json"

    def prepare_locked(self, before: dict, candidate: str) -> None:
        if self.backend.snapshot() != before:
            raise tx.StalePlan("Runtime hostname changed before arming")
        if self.manager.store.snapshot(self.path)["kind"] != "absent":
            raise tx.TransactionError("Runtime hostname journal already exists")
        self.manager._save(self.path, {"schema_version": 1, "run_id": self.run_id, "before": before,
                                      "candidate": bootstrap.validate_hostname(candidate), "phase": "prepared"})

    def load(self) -> dict:
        value = self.manager._load(self.path)
        if (value.get("schema_version") != 1 or value.get("run_id") != self.run_id or value.get("phase") not in HOST_PHASES
                or not isinstance(value.get("before"), dict) or set(value["before"]) != {"hostname", "namespace"}
                or not isinstance(value["before"]["hostname"], str)
                or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", value["before"]["hostname"])
                or bootstrap.validate_hostname(value.get("candidate")) != value["candidate"]):
            raise tx.TransactionError("Invalid runtime hostname journal")
        identity = value["before"]["namespace"]
        if identity is not None and (not isinstance(identity, dict) or set(identity) != {"device", "inode"}
                                     or any(type(identity[k]) is not int or identity[k] <= 0 for k in identity)):
            raise tx.TransactionError("Invalid hostname namespace identity")
        return value

    def apply_locked(self) -> None:
        value = self.load()
        if value["phase"] != "prepared" or self.backend.snapshot() != value["before"]:
            raise tx.StalePlan("Runtime hostname changed before application")
        if value["before"]["hostname"] == value["candidate"]:
            value["phase"] = "reused"
        else:
            value["phase"] = "intent"
            self.manager._save(self.path, value)
            self.backend.set(value["candidate"])
            value["phase"] = "done"
        self.manager._save(self.path, value)

    def recover_locked(self, *, boot: bool = False) -> None:
        value = self.load()
        if value["phase"] in {"rolled_back", "expired_on_boot"}:
            return
        if boot and self.manager.fs.root != Path("/"):
            value["phase"] = "expired_on_boot"
        elif value["phase"] in {"prepared", "reused"}:
            value["phase"] = "rolled_back"
        else:
            try:
                current = self.backend.snapshot()
                if current["namespace"] != value["before"]["namespace"]:
                    raise tx.RecoveryError("Replacement hostname namespace preserved")
                if current["hostname"] != value["before"]["hostname"]:
                    if current["hostname"] != value["candidate"]:
                        raise tx.RecoveryError("External runtime hostname edit preserved")
                    self.backend.set(value["before"]["hostname"])
                if self.backend.snapshot() != value["before"]:
                    raise tx.RecoveryError("Original runtime hostname was not restored")
                value["phase"] = "rolled_back"
            except (tx.TransactionError, OSError, ValueError, subprocess.SubprocessError):
                value["phase"] = "recovery_failed"
                self.manager._save(self.path, value)
                raise
        self.manager._save(self.path, value)

    def verify_locked(self) -> None:
        value = self.load()
        if value["phase"] not in {"done", "reused"} or self.backend.snapshot() != {**value["before"], "hostname": value["candidate"]}:
            raise tx.TransactionError("Runtime hostname health changed before acknowledgment")


def network_operations(profile, before: dict, *, ssh_route: dict | None = None) -> tuple[list, list]:
    """Retain old addresses until acknowledgment; never flush/restart networking."""
    apply, deferred = [], []
    iface = profile.interface
    original = before["objects"]
    addresses = {family: [obj for obj in original if obj["kind"] == "address" and obj["family"] == family] for family in (4, 6)}
    defaults = {family: [obj for obj in original if obj["kind"] == "route" and obj["family"] == family
                         and obj["dst"] == ("0.0.0.0/0" if family == 4 else "::/0")] for family in (4, 6)}
    if any(len(addresses[f]) > 1 or len(defaults[f]) > 1 for f in (4, 6)):
        raise tx.TransactionError("Base requires one current static address and default per family")
    def op(stage, action, obj):
        stage.append({"action": action, "object": net.normalized_object(obj, iface)})
    if ssh_route is not None:
        protected = net.normalized_object(ssh_route, iface)
        if protected["protocol"] == "kernel":
            raise tx.TransactionError("SSH preservation must use an explicit static host route")
        if not any(net.identity(obj) == net.identity(protected) for obj in original):
            op(apply, "add", protected)
            op(deferred, "delete", protected)
        elif protected not in original:
            raise tx.StalePlan("SSH preservation route conflicts with existing state")
    for family, cidr, gateway in ((4, profile.ipv4_cidr, profile.ipv4_gateway), (6, profile.ipv6_cidr, profile.ipv6_gateway)):
        old_address = addresses[family][0] if addresses[family] else None
        old_default = defaults[family][0] if defaults[family] else None
        if cidr is None:
            if old_default is not None:
                op(apply, "delete", old_default)
            if old_address is not None:
                op(deferred, "delete", old_address)
            continue
        interface = ipaddress.ip_interface(cidr)
        candidate = {"kind": "address", "family": family, "cidr": cidr}
        if old_address is not None:
            old = ipaddress.ip_interface(old_address["cidr"])
            if old.ip == interface.ip and old != interface:
                raise tx.TransactionError("Changing the prefix of an existing address requires a separate migration")
            if family == 4 and old != interface and old.network == interface.network:
                raise tx.TransactionError("An IPv4 move within the same prefix requires an explicit secondary-address migration")
            if old == interface:
                candidate = old_address
            else:
                op(deferred, "delete", old_address)
        if family == 4 and interface.network.prefixlen < 31 and candidate is not old_address:
            candidate["broadcast"] = str(interface.network.broadcast_address)
        op(apply, "add", candidate)
        if family == 4 and ipaddress.ip_address(gateway) not in interface.network:
            direct = [obj for obj in original if obj["kind"] == "route" and obj["family"] == 4
                      and obj["dst"] == gateway + "/32" and "gateway" not in obj]
            reusable = next((obj for obj in direct if obj["protocol"] != "kernel" and "src" not in obj), None)
            retained_kernel = old_address == candidate and any(obj["protocol"] == "kernel" for obj in direct)
            if reusable is not None:
                op(apply, "add", reusable)
            elif not retained_kernel:
                metric = 0
                while any(obj.get("metric") == metric for obj in direct):
                    metric += 1
                op(apply, "add", {"kind": "route", "family": 4, "dst": gateway + "/32", "metric": metric,
                                  "protocol": "static", "scope": "link"})
        target = {"kind": "route", "family": family, "dst": "0.0.0.0/0" if family == 4 else "::/0",
                  "gateway": gateway, "protocol": "static", "scope": "global", "metric": 0 if family == 4 else 1024}
        if family == 4:
            target["src"] = str(interface.ip)
        if old_default is not None:
            if old_default["protocol"] == "kernel":
                raise tx.TransactionError("A kernel-owned default requires a separate migration")
            target.update(metric=old_default["metric"], protocol=old_default["protocol"])
            if old_default.get("gateway") == gateway and old_default.get("src", str(interface.ip)) == str(interface.ip):
                target = old_default
            else:
                op(apply, "delete", old_default)
        op(apply, "add", target)
    return apply, deferred


def preservation_route(network, profile, before: dict, origin: dict | None) -> dict | None:
    if origin is None:
        return None
    endpoint = origin["connection"]
    peer, source = endpoint["client_address"], endpoint["server_address"]
    address = ipaddress.ip_address(source)
    if not any(obj["kind"] == "address" and str(ipaddress.ip_interface(obj["cidr"]).ip) == source for obj in before["objects"]):
        raise tx.TransactionError("The original SSH endpoint is not on the reviewed Base interface")
    destination = str(ipaddress.ip_network(peer + ("/32" if address.version == 4 else "/128")))
    if any(obj["kind"] == "route" and obj["family"] == address.version and obj["dst"] == destination for obj in before["objects"]):
        return None  # An unchanged original host route already protects this peer.
    raw = network.command(["-j", f"-{address.version}", "route", "get", peer, "from", source, "oif", profile.interface])
    if len(raw) > 1024 * 1024:
        raise tx.TransactionError("Original SSH route exceeds its read limit")
    values = json.loads(raw)
    if (not isinstance(values, list) or len(values) != 1 or not isinstance(values[0], dict)
            or values[0].get("dev") != profile.interface or values[0].get("table", "main") not in {"main", 254}
            or values[0].get("type", "unicast") != "unicast"
            or set(values[0]) & {"multipath", "nhid", "encap"}):
        raise tx.TransactionError("The original SSH path cannot be preserved by a simple host route")
    metric = next((candidate for candidate in range(41300, 41556)
                   if not any(obj["kind"] == "route" and obj["family"] == address.version
                              and obj["dst"] == destination and obj["metric"] == candidate for obj in before["objects"])), None)
    if metric is None:
        raise tx.TransactionError("No free SSH preservation route metric")
    result = {"kind": "route", "family": address.version, "dst": destination, "src": source,
              "protocol": "static", "metric": metric,
              "scope": "link" if address.version == 4 and "gateway" not in values[0] else "global"}
    if "gateway" in values[0]:
        result["gateway"] = values[0]["gateway"]
    return net.normalized_object(result, profile.interface)


def validate_config(value: dict) -> dict:
    if (not isinstance(value, dict) or set(value) != {"schema_version", "profile", "package_before", "hostname_before",
                                                   "network_before", "operations", "deferred_operations", "account",
                                                   "ssh_origin", "ssh_preserve_route"}
            or value["schema_version"] != 1 or type(value["schema_version"]) is not int):
        raise tx.TransactionError("Invalid Base contract")
    if not isinstance(value["profile"], dict):
        raise tx.TransactionError("Invalid Base profile")
    try:
        profile = bootstrap.Profile.from_dict(value["profile"], current_user=value["profile"].get("user"))
    except ValueError as error:
        raise tx.TransactionError(str(error)) from error
    if profile.to_dict() != value["profile"] or profile.motd:
        raise tx.TransactionError("Base requires a canonical profile without unfinished modules")
    ssh.validate_account(value["account"])
    if value["account"]["name"] != profile.user:
        raise tx.TransactionError("Base profile differs from the invoking account")
    if value["ssh_origin"] is not None:
        ssh.validate_evidence(value["ssh_origin"], value["account"])
    pkg.validate_snapshot(value["package_before"])
    if not value["package_before"]["healthy"]:
        raise tx.TransactionError("Package state must be healthy before Base")
    host = value["hostname_before"]
    if (not isinstance(host, dict) or set(host) != {"hostname", "namespace"} or not isinstance(host["hostname"], str)
            or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", host["hostname"])):
        raise tx.TransactionError("Invalid reviewed runtime hostname")
    identity = host["namespace"]
    if identity is not None and (not isinstance(identity, dict) or set(identity) != {"device", "inode"}
                                 or any(type(identity[k]) is not int or identity[k] <= 0 for k in identity)):
        raise tx.TransactionError("Invalid reviewed hostname namespace identity")
    before = value["network_before"]
    if (not isinstance(before, dict) or set(before) != {"link", "objects", "pending"} or before["pending"] != []
            or not isinstance(before["link"], dict) or before["link"].get("ifname") != profile.interface
            or not isinstance(before["objects"], list)):
        raise tx.TransactionError("Invalid reviewed Base network")
    for obj in before["objects"]:
        if net.normalized_object(obj, profile.interface) != obj:
            raise tx.TransactionError("Noncanonical Base network object")
    for key in ("operations", "deferred_operations"):
        if not isinstance(value[key], list) or len(value[key]) > 64:
            raise tx.TransactionError("Invalid Base network operations")
        for operation in value[key]:
            if (not isinstance(operation, dict) or set(operation) != {"action", "object"}
                    or operation["action"] not in {"add", "delete"}
                    or net.normalized_object(operation["object"], profile.interface) != operation["object"]
                    or operation["object"].get("protocol") == "kernel"):
                raise tx.TransactionError("Invalid typed Base network operation")
    expected, deferred = network_operations(profile, before, ssh_route=value["ssh_preserve_route"])
    if value["operations"] != expected or value["deferred_operations"] != deferred:
        raise tx.TransactionError("Base network operations differ from the reviewed profile")
    return value


def prepare_review(profile, report: dict, *, network, hostname, packages, inspector=None) -> dict:
    if profile.motd:
        raise tx.TransactionError("MOTD needs its native noninteractive installer before an integrated apply")
    if report.get("file_plan_available") is not True or report.get("blockers") != []:
        raise tx.TransactionError("An unblocked complete host plan is required")
    inspector = inspector or ssh.SSHInspector()
    account = inspector.account()
    if any(report["facts"]["account"].get(key) != account[key] for key in account):
        raise tx.StalePlan("Invoking account differs from the reviewed host plan")
    facts = report["facts"]["account"]
    required = {"/etc/hostname", "/etc/hosts", "/etc/network/interfaces", "/etc/resolv.conf", "/etc/default/locale",
                "/etc/localtime", "/etc/timezone", "/etc/apt/sources.list", facts["home"].rstrip("/") + "/.profile"}
    candidates = {entry["path"]: entry["after"] for entry in report["files"]}
    if not required <= set(candidates) or candidates["/etc/hostname"].get("content") != profile.hostname + "\n":
        raise tx.TransactionError("Base requires its complete matching staged file set")
    package_before = packages.inspect()
    if not package_before["healthy"] or pkg.missing(package_before) != report["facts"]["missing_base_packages"]:
        raise tx.StalePlan("Reviewed package inventory changed or needs manual repair")
    before = network.snapshot()
    origin = inspector.capture(account, required=False)
    ssh_route = preservation_route(network, profile, before, origin)
    operations, deferred = network_operations(profile, before, ssh_route=ssh_route)
    value = {"schema_version": 1, "profile": profile.to_dict(), "package_before": package_before,
             "hostname_before": hostname.snapshot(), "network_before": before,
             "operations": operations, "deferred_operations": deferred, "account": account,
             "ssh_origin": origin, "ssh_preserve_route": ssh_route}
    reviewed = copy.deepcopy(report)
    reviewed["base_apply"] = validate_config(value)
    return reviewed


def launch_reviewed(manager, supervisor, report: dict, *, refresh, confirm=input, output=print,
                    timeout=600, namespace: str | None = None) -> str | None:
    """One effective confirmation for isolated targets; never a production flag."""
    if manager.fs.root == Path("/"):
        raise tx.TransactionError("Production Base application remains gated")
    config = validate_config(report.get("base_apply"))
    profile = bootstrap.Profile.from_dict(config["profile"], current_user=config["profile"]["user"])
    from preflight import format_host_plan
    output(bootstrap.format_plan(bootstrap.build_plan(profile)).rsplit("Preview only.", 1)[0].rstrip())
    output(format_host_plan(report, show_diff=True))
    output("Runtime hostname: " + config["hostname_before"]["hostname"] + " -> " + profile.hostname)
    output("Old addresses remain until verified fresh SSH acknowledgment. Installed packages are retained on rollback.")
    answer = confirm("Apply? [y/N] ")
    if not isinstance(answer, str) or answer.strip().lower() not in {"y", "yes", "д", "да"}:
        return None
    run_id = manager.prepare(report, refresh=refresh, force_run=True)
    try:
        supervisor.arm(run_id, report, interface=profile.interface, operations=config["operations"],
                       deferred_operations=config["deferred_operations"], timeout=timeout,
                       namespace=namespace, ipv6_probe=report.get("ipv6_probe"),
                       ssh_targets=[str(ipaddress.ip_interface(cidr).ip) for cidr in (profile.ipv4_cidr, profile.ipv6_cidr) if cidr],
                       base_apply=config)
        supervisor.start(run_id)
    except BaseException:
        try:
            status = manager.status(run_id)
            if status.get("supervised"):
                supervisor.recover(run_id)
            else:
                manager.recover(run_id)
        except (tx.TransactionError, OSError, ValueError, subprocess.SubprocessError):
            pass  # Retain the independent guard and private recovery state.
        raise
    return run_id
