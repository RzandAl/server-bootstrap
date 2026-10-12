"""Journaled static-address/main-route deltas. No flush, shell, or ifupdown restart."""

from __future__ import annotations

import ipaddress
import json
import re
import shutil
import subprocess
import time
from typing import Any

import transaction as tx


SYSTEM_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
INTERFACE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,14}\Z")
NAMESPACE = re.compile(r"rzandal-test-[0-9a-f]{8,32}\Z")


def interface_name(value: str) -> str:
    if not isinstance(value, str) or not INTERFACE.fullmatch(value) or value == "lo":
        raise tx.TransactionError("Unsupported network interface name")
    return value


def integer(value: Any, maximum: int = 2**32 - 1) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise tx.TransactionError("Invalid network integer")
    return value


def address(value: str, family: int, *, gateway: bool = False) -> str:
    parsed = ipaddress.ip_address(value)
    if (parsed.version != family or parsed.is_unspecified or parsed.is_multicast
            or parsed.is_loopback or (parsed.is_link_local and not gateway)
            or (family == 6 and parsed.ipv4_mapped is not None)):
        raise tx.TransactionError("Unsupported network address")
    return str(parsed)


def normalized_object(value: dict[str, Any], interface: str) -> dict[str, Any]:
    """Strict, reversible subset; do not silently drop unknown route attributes."""
    if not isinstance(value, dict) or value.get("family") not in (4, 6) or type(value["family"]) is not int:
        raise tx.TransactionError("Invalid network object family")
    family = value["family"]
    if value.get("kind") == "address":
        if set(value) - {"kind", "family", "cidr", "peer", "broadcast"}:
            raise tx.TransactionError("Unsupported address attributes")
        parsed = ipaddress.ip_interface(value["cidr"])
        address(str(parsed.ip), family)
        if parsed.version != family or parsed.network.prefixlen == 0:
            raise tx.TransactionError("Invalid address prefix")
        result = {"kind": "address", "family": family, "cidr": str(parsed)}
        if value.get("peer") is not None:
            if family != 4 or parsed.network.prefixlen != 32:
                raise tx.TransactionError("Only IPv4 /32 point-to-point addresses are supported")
            peer = ipaddress.ip_interface(value["peer"])
            if peer.version != 4 or peer.network.prefixlen != 32:
                raise tx.TransactionError("Invalid point-to-point peer")
            result["peer"] = address(str(peer.ip), 4, gateway=True) + "/32"
        if value.get("broadcast") is not None:
            if family != 4:
                raise tx.TransactionError("IPv6 has no broadcast address")
            result["broadcast"] = str(ipaddress.IPv4Address(value["broadcast"]))
        return result
    if value.get("kind") != "route" or set(value) - {"kind", "family", "dst", "gateway", "src", "metric", "protocol", "scope", "onlink", "pref"}:
        raise tx.TransactionError("Unsupported route attributes")
    network = ipaddress.ip_network(value["dst"], strict=True)
    if network.version != family:
        raise tx.TransactionError("Invalid route family")
    result = {"kind": "route", "family": family, "dst": str(network),
              "metric": integer(value.get("metric", 1024 if family == 6 else 0)), "protocol": value.get("protocol", "boot"),
              "scope": value.get("scope", "global"), "onlink": value.get("onlink", False)}
    if (not isinstance(result["protocol"], str) or not isinstance(result["scope"], str)
            or result["protocol"] not in {"static", "boot", "kernel"}
            or result["scope"] not in {"global", "link", "host"} or type(result["onlink"]) is not bool):
        raise tx.TransactionError("Unsupported route protocol, scope, or flags")
    for key in ("gateway", "src"):
        if value.get(key) is not None:
            result[key] = address(value[key], family, gateway=key == "gateway")
    if family == 6 or value.get("pref") is not None:
        pref = value.get("pref", "medium")
        if family != 6 or not isinstance(pref, str) or pref not in {"low", "medium", "high"}:
            raise tx.TransactionError("Invalid IPv6 route preference")
        result["pref"] = pref
    return result


def identity(value: dict[str, Any]) -> tuple[Any, ...]:
    if value["kind"] == "address":
        return value["kind"], value["family"], str(ipaddress.ip_interface(value["cidr"]).ip)
    return value["kind"], value["family"], value["dst"], value["metric"]


class IPBackend:
    def __init__(self, interface: str, *, namespace: str | None = None):
        self.interface = interface_name(interface)
        if namespace is not None and (not isinstance(namespace, str) or not NAMESPACE.fullmatch(namespace)):
            raise tx.TransactionError("Only named fixture namespaces are supported")
        self.namespace = namespace

    def command(self, arguments: list[str]) -> str:
        executable = shutil.which("ip", path=SYSTEM_PATH)
        if not executable:
            raise tx.TransactionError("iproute2 is required for network recovery")
        prefix = [executable, "-n", self.namespace] if self.namespace else [executable]
        result = subprocess.run([*prefix, *arguments], capture_output=True, text=True, timeout=10,
                                check=False, env={"PATH": SYSTEM_PATH, "LC_ALL": "C"})
        if result.returncode:
            raise tx.RecoveryError("ip failed: " + result.stderr.strip())
        return result.stdout

    def snapshot(self, *, allow_dad: bool = False) -> dict[str, Any]:
        links = json.loads(self.command(["-j", "address", "show", "dev", self.interface]))
        if not isinstance(links, list) or len(links) != 1 or links[0].get("ifname") != self.interface:
            raise tx.TransactionError("Cannot establish selected interface identity")
        link = links[0]
        if link.get("link_type") != "ether" or "UP" not in link.get("flags", []):
            raise tx.TransactionError("Recovery requires an existing UP Ethernet interface")
        items = []
        pending = []
        for value in link.get("addr_info", []):
            if value.get("scope") != "global":
                continue
            family = {"inet": 4, "inet6": 6}.get(value.get("family"))
            if family is None:
                raise tx.TransactionError("Unknown address family")
            flags = set(value.get("flags", []))
            allowed_flags = {"permanent", "tentative", "dadfailed"} | ({"secondary"} if allow_dad else set())
            if (flags - allowed_flags or any(value.get(key) for key in ("noprefixroute", "mngtmpaddr", "temporary", "deprecated"))
                    or (value.get("secondary") and not allow_dad)):
                raise tx.TransactionError("Unsupported address flags require another backend")
            if value.get("dadfailed") or "dadfailed" in flags:
                raise tx.RecoveryError("IPv6 address failed DAD")
            if value.get("tentative") or "tentative" in flags:
                if not allow_dad:
                    raise tx.RecoveryError("IPv6 address is still tentative")
                pending.append(value.get("local"))
            if (value.get("dynamic") or flags & {"dynamic", "temporary", "deprecated"}
                    or any(value.get(key, "forever") not in {"forever", 4294967295}
                           for key in ("valid_life_time", "preferred_life_time"))):
                raise tx.TransactionError("Dynamic or finite-lifetime addresses require another backend")
            if value.get("label", self.interface) != self.interface:
                raise tx.TransactionError("Address aliases require another backend")
            obj = {"kind": "address", "family": family, "cidr": f"{value['local']}/{value['prefixlen']}"}
            if "peer" in value:
                obj["peer"] = value["peer"] if "/" in value["peer"] else value["peer"] + "/32"
            if "broadcast" in value:
                obj["broadcast"] = value["broadcast"]
            items.append(normalized_object(obj, self.interface))
        for family in (4, 6):
            routes = json.loads(self.command(["-j", f"-{family}", "route", "show", "table", "main", "dev", self.interface]))
            if not isinstance(routes, list):
                raise tx.TransactionError("Cannot inspect main-table routes")
            for value in routes:
                if (not isinstance(value, dict) or value.get("dev") != self.interface
                        or set(value) - {"dst", "gateway", "dev", "protocol", "scope", "prefsrc", "metric", "flags", "pref", "table", "type"}
                        or value.get("table", "main") not in {"main", 254}
                        or value.get("type", "unicast") != "unicast" or set(value.get("flags", [])) - {"onlink"}):
                    raise tx.TransactionError("Complex or dynamic route requires another backend")
                obj = {"kind": "route", "family": family, "dst": value.get("dst", "default"),
                       "protocol": value.get("protocol", "boot"), "scope": value.get("scope", "global"),
                       "metric": value.get("metric", 1024 if family == 6 else 0), "onlink": "onlink" in value.get("flags", [])}
                if obj["dst"] == "default":
                    obj["dst"] = "0.0.0.0/0" if family == 4 else "::/0"
                for source, target in (("gateway", "gateway"), ("prefsrc", "src"), ("pref", "pref")):
                    if source in value:
                        obj[target] = value[source]
                items.append(normalized_object(obj, self.interface))
        keys = [identity(item) for item in items]
        if len(set(keys)) != len(keys):
            raise tx.TransactionError("Ambiguous network object identity")
        return {"link": {"ifindex": integer(link["ifindex"]), "ifname": self.interface,
                         "address": link.get("address"), "mtu": integer(link["mtu"])},
                "objects": sorted(items, key=lambda item: json.dumps(item, sort_keys=True)), "pending": sorted(pending)}

    def mutate(self, action: str, value: dict[str, Any]) -> None:
        if action not in {"add", "delete"}:
            raise tx.TransactionError("Invalid network action")
        obj = normalized_object(value, self.interface)
        if obj["kind"] == "address":
            arguments = [f"-{obj['family']}", "address", "add" if action == "add" else "del", obj["cidr"]]
            for key in ("peer", "broadcast"):
                if key in obj:
                    arguments.extend([key, obj[key]])
            arguments.extend(["dev", self.interface, "scope", "global"])
        else:
            if obj["protocol"] == "kernel":
                raise tx.TransactionError("Kernel routes belong to their addresses; never mutate them directly")
            arguments = [f"-{obj['family']}", "route", "add" if action == "add" else "del", obj["dst"]]
            if "gateway" in obj:
                arguments.extend(["via", obj["gateway"]])
            arguments.extend(["dev", self.interface, "table", "main", "proto", obj["protocol"],
                              "scope", obj["scope"], "metric", str(obj["metric"])])
            if "src" in obj:
                arguments.extend(["src", obj["src"]])
            if obj["onlink"]:
                arguments.append("onlink")
            if "pref" in obj:
                arguments.extend(["pref", obj["pref"]])
        self.command(arguments)

    def settled(self) -> dict[str, Any]:
        deadline = time.monotonic() + 8
        while True:
            snapshot = self.snapshot(allow_dad=True)
            if not snapshot["pending"]:
                return snapshot
            if time.monotonic() >= deadline:
                raise tx.RecoveryError("IPv6 DAD did not finish within the recovery timeout")
            time.sleep(0.1)


class NetworkJournal:
    """Methods with a _locked suffix share FileTransaction's existing lock."""

    def __init__(self, manager: tx.FileTransaction, run_id: str, backend: IPBackend):
        manager._run_id(run_id)
        self.manager, self.run_id, self.backend = manager, run_id, backend
        self.path = f"/runs/{run_id}/network.json"

    def prepare_locked(self, operations: list[dict[str, Any]]) -> None:
        if self.manager.store.snapshot(self.path)["kind"] != "absent":
            raise tx.TransactionError("Network journal already exists")
        if not isinstance(operations, list) or len(operations) > 64:
            raise tx.TransactionError("Invalid network operation list")
        before = self.backend.snapshot()
        projected = {identity(obj): obj for obj in before["objects"]}
        entries = []
        for operation in operations:
            if not isinstance(operation, dict) or set(operation) != {"action", "object"} or operation["action"] not in {"add", "delete"}:
                raise tx.TransactionError("Invalid network operation")
            obj = normalized_object(operation["object"], self.backend.interface)
            if obj["kind"] == "route" and obj["protocol"] == "kernel":
                raise tx.TransactionError("Kernel routes may not be explicit operations")
            key = identity(obj)
            current = projected.get(key)
            if current is not None and current != obj:
                raise tx.StalePlan("Network object conflicts with an existing address or route")
            owned = (current is None) if operation["action"] == "add" else (current is not None)
            entries.append({"action": operation["action"], "object": obj, "owned": owned, "phase": "pending"})
            if owned:
                if operation["action"] == "add":
                    projected[key] = obj
                else:
                    projected.pop(key)
        self.manager._save(self.path, {"schema_version": 1, "run_id": self.run_id,
                           "interface": self.backend.interface, "namespace": self.backend.namespace,
                           "before": before, "operations": entries, "phase": "prepared"})

    def load(self) -> dict[str, Any]:
        data = self.manager._load(self.path)
        if (data.get("schema_version") != 1 or data.get("run_id") != self.run_id
                or data.get("interface") != self.backend.interface or data.get("namespace") != self.backend.namespace
                or not isinstance(data.get("phase"), str)
                or data["phase"] not in {"prepared", "applying", "applied", "rolling_back", "rolled_back", "recovery_failed", "expired_on_boot"}
                or not isinstance(data.get("operations"), list) or len(data["operations"]) > 64):
            raise tx.TransactionError("Invalid network journal")
        before = data.get("before")
        if (not isinstance(before, dict) or set(before) != {"link", "objects", "pending"}
                or not isinstance(before["link"], dict) or before["link"].get("ifname") != self.backend.interface
                or not isinstance(before["objects"], list) or before["pending"] != []):
            raise tx.TransactionError("Invalid original network snapshot")
        integer(before["link"].get("ifindex"))
        integer(before["link"].get("mtu"))
        for obj in before["objects"]:
            if normalized_object(obj, self.backend.interface) != obj:
                raise tx.TransactionError("Invalid original network object")
        for entry in data["operations"]:
            if (not isinstance(entry, dict) or set(entry) != {"action", "object", "owned", "phase"}
                    or entry["action"] not in {"add", "delete"} or type(entry["owned"]) is not bool
                    or not isinstance(entry["phase"], str) or entry["phase"] not in {"pending", "intent", "done", "undone"}
                    or normalized_object(entry["object"], self.backend.interface) != entry["object"]):
                raise tx.TransactionError("Invalid journaled network operation")
        return data

    def current(self, data: dict[str, Any]) -> dict[tuple[Any, ...], dict[str, Any]]:
        snapshot = self.backend.settled()
        if snapshot["link"] != data["before"]["link"]:
            raise tx.StalePlan("Interface identity, MAC, or MTU changed; refusing to touch a replacement link")
        return {identity(obj): obj for obj in snapshot["objects"]}

    def apply_locked(self) -> None:
        data = self.load()
        if data["phase"] != "prepared" or self.backend.snapshot() != data["before"]:
            raise tx.StalePlan("Network changed after review")
        data["phase"] = "applying"
        self.manager._save(self.path, data)
        for entry in data["operations"]:
            if not entry["owned"]:
                entry["phase"] = "done"
                self.manager._save(self.path, data)
                continue
            current = self.current(data).get(identity(entry["object"]))
            expected = None if entry["action"] == "add" else entry["object"]
            if current != expected:
                raise tx.StalePlan("Network object changed before mutation")
            entry["phase"] = "intent"
            self.manager._save(self.path, data)
            self.backend.mutate(entry["action"], entry["object"])
            expected = entry["object"] if entry["action"] == "add" else None
            if self.current(data).get(identity(entry["object"])) != expected:
                raise tx.RecoveryError("Network command did not produce its expected state")
            entry["phase"] = "done"
            self.manager._save(self.path, data)
        data["phase"] = "applied"
        self.manager._save(self.path, data)

    def recover_locked(self, *, boot: bool = False) -> None:
        data = self.load()
        if data["phase"] in {"rolled_back", "expired_on_boot"}:
            return
        if boot:
            # Old kernel state does not survive boot. Restore files before the
            # network manager starts; never replay obsolete interface indices.
            data["phase"] = "expired_on_boot"
            self.manager._save(self.path, data)
            return
        data["phase"] = "rolling_back"
        self.manager._save(self.path, data)
        failures = []
        reversed_entries = list(reversed(data["operations"]))
        # Delete candidate addresses before restoring originals. Restoring an old
        # IPv4 address as a secondary and then deleting the candidate primary can
        # let the kernel delete the restored secondary too. Restore routes last.
        ordered = [entry for entry in reversed_entries if entry["object"]["kind"] == "address" and entry["action"] == "add"]
        ordered += [entry for entry in reversed_entries if entry["object"]["kind"] == "address" and entry["action"] == "delete"]
        ordered += [entry for entry in reversed_entries if entry["object"]["kind"] == "route"]
        for entry in ordered:
            if not entry["owned"] or entry["phase"] in {"pending", "undone"}:
                continue
            try:
                current = self.current(data).get(identity(entry["object"]))
                original = None if entry["action"] == "add" else entry["object"]
                candidate = entry["object"] if entry["action"] == "add" else None
                if current != original:
                    if current != candidate:
                        raise tx.RecoveryError("External network change preserved for manual review")
                    self.backend.mutate("delete" if entry["action"] == "add" else "add", entry["object"])
                    if self.current(data).get(identity(entry["object"])) != original:
                        raise tx.RecoveryError("Network restoration did not produce its expected state")
                entry["phase"] = "undone"
                self.manager._save(self.path, data)
            except (tx.TransactionError, OSError, ValueError, subprocess.SubprocessError) as error:
                failures.append(str(error))
        try:
            current = self.current(data)
            if any(current.get(identity(obj)) != obj for obj in data["before"]["objects"]):
                failures.append("Original address/route inventory has not been fully restored")
        except (tx.TransactionError, OSError, ValueError, subprocess.SubprocessError) as error:
            failures.append(str(error))
        data["phase"] = "recovery_failed" if failures else "rolled_back"
        data["failures"] = failures
        self.manager._save(self.path, data)
        if failures:
            raise tx.RecoveryError("; ".join(failures))

    def verify_applied_locked(self) -> None:
        data = self.load()
        if data["phase"] != "applied":
            raise tx.TransactionError("Network application has not completed")
        current = self.current(data)
        expected = {}
        for entry in data["operations"]:
            if entry["owned"]:
                expected[identity(entry["object"])] = entry["object"] if entry["action"] == "add" else None
        if any(current.get(key) != obj for key, obj in expected.items()):
            raise tx.StalePlan("Applied network changed before acknowledgment")
