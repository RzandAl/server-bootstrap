"""Owned temporary IPv6 checks; no permanent files or main-route replacement."""

from __future__ import annotations

import copy
import ipaddress
import json
import re
import shutil
import subprocess
import sys
import time
from typing import Any

import transaction as tx
import network_recovery as net

bootstrap = sys.modules.get("bootstrap")
if bootstrap is None:
    raise RuntimeError("IPv6 probe requires the trusted recovery module loader")

DAD_SECONDS = 8
CONNECT_SECONDS = 4
TABLE_BASE, PRIORITY_BASE, MARK_BASE, SLOT_COUNT = 41200, 10000, 0x525A0000, 256
PHASES = {"prepared", "probing", "cleaning", "passed", "failed", "recovery_failed", "expired_on_boot"}

# Fixed trusted code with a JSON data argument. No profile supplies executable
# text. A separate process also works inside an owned CI network namespace and
# dies with the supervised worker's control group.
TCP_CODE = r'''
import ipaddress, json, socket, sys
p = json.loads(sys.argv[1])
result = {"connected": False, "source": None, "target": p["target"], "port": p["port"], "mark": None, "error": None}
try:
    with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
        s.settimeout(p["timeout"])
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, p["interface"].encode("ascii") + b"\0")
        s.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, p["mark"])
        s.bind((p["source"], 0, 0, 0))
        s.connect((p["target"], p["port"], 0, 0))
        result.update(connected=True, source=str(ipaddress.ip_address(s.getsockname()[0])),
                      mark=s.getsockopt(socket.SOL_SOCKET, socket.SO_MARK))
except OSError as e:
    result["error"] = type(e).__name__ + ": " + str(e)
print(json.dumps(result))
'''


def validate_config(value: Any) -> dict:
    try:
        if not isinstance(value, dict) or set(value) != {"cidr", "gateway", "targets"}:
            raise tx.TransactionError("Invalid IPv6 probe configuration")
        interface = bootstrap.parse_cidr(value["cidr"], 6, "IPv6 probe address")
        gateway = bootstrap.parse_address(value["gateway"], 6, "IPv6 probe gateway")
        if gateway == interface.ip or (not gateway.is_link_local and gateway not in interface.network):
            raise tx.TransactionError("IPv6 probe supports an in-prefix or link-local gateway")
        targets = value["targets"]
        if not isinstance(targets, list) or not 1 <= len(targets) <= 2:
            raise tx.TransactionError("IPv6 probe needs one or two typed TCP destinations")
        normalized = []
        for target in targets:
            if not isinstance(target, dict) or set(target) != {"address", "port"}:
                raise tx.TransactionError("Invalid IPv6 probe TCP target")
            address = bootstrap.parse_address(target["address"], 6, "IPv6 probe target")
            if address.is_link_local or address in interface.network or address == gateway:
                raise tx.TransactionError("External probe targets must lie outside the candidate subnet")
            port = target["port"]
            if type(port) is not int or not 1 <= port <= 65535:
                raise tx.TransactionError("Invalid IPv6 probe TCP port")
            normalized.append({"address": str(address), "port": port})
        if len({(item["address"], item["port"]) for item in normalized}) != len(normalized):
            raise tx.TransactionError("Duplicate IPv6 probe TCP target")
        return {"cidr": str(interface), "gateway": str(gateway), "targets": normalized}
    except (ValueError, TypeError, KeyError) as error:
        raise tx.TransactionError(str(error)) from error


def table_id(value: Any) -> int:
    names = {"unspec": 0, "default": 253, "main": 254, "local": 255}
    if isinstance(value, str) and value in names:
        return names[value]
    if isinstance(value, str) and value.isdecimal():
        value = int(value)
    return net.integer(value)


def mark_value(value: Any) -> int:
    if isinstance(value, str) and re.fullmatch(r"(?:0x[0-9a-fA-F]{1,8}|[0-9]{1,10})", value):
        value = int(value, 16 if value.startswith("0x") else 10)
    return net.integer(value)


def objects(config: dict, allocation: dict, *, reused: bool) -> list[dict]:
    source = str(ipaddress.ip_interface(config["cidr"]).ip)
    route = {"kind": "route", "family": 6, "metric": 1024, "protocol": "static", "onlink": False,
             "pref": "medium", "table": allocation["table"]}
    return [
        {"kind": "address", "cidr": config["cidr"], "mode": "regular" if reused else "probe"},
        {**route, "dst": config["gateway"] + "/128", "scope": "link"},
        {**route, "dst": "::/0", "scope": "global", "gateway": config["gateway"]},
        {"kind": "rule", "priority": allocation["priority"], "source": source + "/128",
         "mark": allocation["mark"], "mask": 0xffffffff, "table": allocation["table"], "protocol": "static"},
    ]


class TCPConnector:
    def connect(self, backend: net.IPBackend, source: str, target: dict, mark: int) -> dict:
        payload = {"interface": backend.interface, "source": source, "target": target["address"],
                   "port": target["port"], "mark": mark, "timeout": CONNECT_SECONDS}
        arguments = ["/usr/bin/python3", "-I", "-c", TCP_CODE, json.dumps(payload)]
        if backend.namespace is not None:
            executable = shutil.which("ip", path=net.SYSTEM_PATH)
            if executable is None:
                raise tx.TransactionError("iproute2 is required for a fixture probe")
            arguments = [executable, "netns", "exec", backend.namespace, *arguments]
        result = subprocess.run(arguments, capture_output=True, text=True, timeout=CONNECT_SECONDS + 3,
                                check=False, env={"PATH": net.SYSTEM_PATH, "LC_ALL": "C"})
        if result.returncode or len(result.stdout) > 4096:
            raise tx.RecoveryError("Bound IPv6 connector failed: " + result.stderr.strip())
        value = json.loads(result.stdout)
        if (not isinstance(value, dict) or set(value) != {"connected", "source", "target", "port", "mark", "error"}
                or type(value["connected"]) is not bool or value["target"] != target["address"]
                or value["port"] != target["port"]
                or (value["connected"] and (value["source"] != source or value["mark"] != mark))):
            raise tx.RecoveryError("TCP probe did not establish its required source/mark identity")
        return value


class ProbeBackend(net.IPBackend):
    def values(self, arguments: list[str]) -> list[dict]:
        raw = self.command(["-j", *arguments])
        if len(raw) > 1024 * 1024:
            raise tx.TransactionError("IPv6 probe inventory exceeds its read limit")
        value = json.loads(raw)
        if not isinstance(value, list) or len(value) > 4096 or any(not isinstance(item, dict) for item in value):
            raise tx.TransactionError("Malformed IPv6 probe inventory")
        return value

    def link(self) -> dict:
        links = self.values(["link", "show", "dev", self.interface])
        if len(links) != 1 or links[0].get("ifname") != self.interface or "UP" not in links[0].get("flags", []):
            raise tx.RecoveryError("IPv6 probe interface is absent or no longer UP")
        value = links[0]
        if (type(value.get("ifindex")) is not int or value["ifindex"] <= 0
                or type(value.get("mtu")) is not int or value["mtu"] <= 0
                or not isinstance(value.get("address"), str)
                or not re.fullmatch(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", value["address"])):
            raise tx.RecoveryError("IPv6 probe interface identity is incomplete")
        return {"ifindex": value["ifindex"], "ifname": self.interface, "address": value["address"], "mtu": value["mtu"]}

    def all_routes(self) -> list[dict]:
        return [entry for family in (4, 6) for entry in self.values([f"-{family}", "route", "show", "table", "all"])]

    def rules(self) -> list[dict]:
        return self.values(["-6", "rule", "show"])

    def allocate(self, run_id: str) -> dict:
        routes, rules = self.all_routes(), self.rules()
        occupied_tables = {table_id(item.get("table", 254)) for item in routes}
        occupied_tables.update(table_id(item["table"]) for item in rules if "table" in item)
        priorities = {net.integer(item["priority"]) for item in rules}
        for step in range(SLOT_COUNT):
            slot = (int(run_id[-2:], 16) + step) % SLOT_COUNT
            table, priority, mark = TABLE_BASE + slot, PRIORITY_BASE + slot, MARK_BASE + slot
            collision = any((mark & mark_value(rule.get("fwmask", 0xffffffff))) ==
                            (mark_value(rule["fwmark"]) & mark_value(rule.get("fwmask", 0xffffffff)))
                            for rule in rules if "fwmark" in rule)
            if table not in occupied_tables and priority not in priorities and not collision:
                return {"table": table, "priority": priority, "mark": mark}
        raise tx.TransactionError("No unused IPv6 probe table/priority/packet mark is available")

    def address_info(self, config: dict) -> dict | None:
        source = str(ipaddress.ip_interface(config["cidr"]).ip)
        links = self.values(["-6", "address", "show", "dev", self.interface])
        matches = [item for link in links for item in link.get("addr_info", []) if item.get("local") == source]
        if len(matches) > 1:
            raise tx.RecoveryError("Ambiguous IPv6 candidate address identity")
        return matches[0] if matches else None

    def current_address(self, config: dict) -> dict | None:
        info = self.address_info(config)
        if info is None:
            return None
        flags = set(info.get("flags", [])) | {key for key in ("permanent", "deprecated", "noprefixroute", "tentative", "dadfailed",
                                                              "dynamic", "temporary", "mngtmpaddr", "nodad", "optimistic") if info.get(key)}
        valid = info.get("valid_life_time") in ("forever", 4294967295)
        preferred = info.get("preferred_life_time")
        base = (info.get("scope") == "global" and info.get("label", self.interface) == self.interface
                and not flags - {"permanent", "deprecated", "noprefixroute", "tentative", "dadfailed"})
        mode = "external"
        if base and valid:
            if "noprefixroute" in flags and type(preferred) is int and preferred == 0:
                mode = "probe"
            elif "noprefixroute" not in flags and "deprecated" not in flags and preferred in ("forever", 4294967295):
                mode = "regular"
        return {"kind": "address", "cidr": f"{info['local']}/{info['prefixlen']}", "mode": mode}

    def current_routes(self, allocation: dict) -> list[dict]:
        values = []
        for value in self.all_routes():
            if table_id(value.get("table", 254)) != allocation["table"]:
                continue
            known = {"dst", "gateway", "dev", "protocol", "scope", "prefsrc", "metric", "flags", "pref", "table", "type"}
            if set(value) - known or value.get("dev") != self.interface or value.get("type", "unicast") != "unicast":
                values.append({"kind": "external", "raw": value})
                continue
            obj = {"kind": "route", "family": 6, "dst": "::/0" if value.get("dst") == "default" else value["dst"],
                   "protocol": value.get("protocol", "boot"), "scope": value.get("scope", "global"),
                   "metric": value.get("metric", 1024), "onlink": "onlink" in value.get("flags", []), "pref": value.get("pref", "medium")}
            if set(value.get("flags", [])) - {"onlink"}:
                values.append({"kind": "external", "raw": value})
                continue
            for old, new in (("gateway", "gateway"), ("prefsrc", "src")):
                if old in value:
                    obj[new] = value[old]
            try:
                values.append({**net.normalized_object(obj, self.interface), "table": allocation["table"]})
            except (ValueError, KeyError, TypeError):
                values.append({"kind": "external", "raw": value})
        return values

    def current_rule(self, config: dict, allocation: dict) -> dict | None:
        matches = [value for value in self.rules() if value.get("priority") == allocation["priority"]]
        if not matches:
            return None
        if len(matches) != 1:
            return {"kind": "external", "raw": matches}
        value = matches[0]
        if (set(value) - {"priority", "src", "from", "dst", "to", "table", "fwmark", "fwmask", "protocol", "flags"}
                or value.get("flags", []) or value.get("dst", value.get("to", "all")) != "all"):
            return {"kind": "external", "raw": value}
        try:
            source = ipaddress.ip_network(value.get("src", value.get("from", "all")), strict=False)
            return {"kind": "rule", "priority": value["priority"], "source": str(source),
                    "mark": mark_value(value["fwmark"]), "mask": mark_value(value.get("fwmask", 0xffffffff)),
                    "table": table_id(value["table"]), "protocol": value.get("protocol", "boot")}
        except (ValueError, KeyError, TypeError):
            return {"kind": "external", "raw": value}

    def current(self, obj: dict, config: dict, allocation: dict) -> dict | None:
        if obj["kind"] == "address":
            return self.current_address(config)
        if obj["kind"] == "rule":
            return self.current_rule(config, allocation)
        matches = [value for value in self.current_routes(allocation) if value.get("dst") == obj["dst"] and value.get("metric") == obj["metric"]]
        external = any(value["kind"] == "external" for value in self.current_routes(allocation))
        return matches[0] if len(matches) == 1 else ({"kind": "external"} if matches or external else None)

    def mutate_probe(self, action: str, obj: dict) -> None:
        if action not in {"add", "delete"}:
            raise tx.TransactionError("Invalid IPv6 probe mutation")
        verb = "add" if action == "add" else "del"
        if obj["kind"] == "address":
            arguments = ["-6", "address", verb, obj["cidr"], "dev", self.interface]
            if action == "add":
                arguments.extend(["scope", "global", "valid_lft", "forever", "preferred_lft", "0", "noprefixroute"])
        elif obj["kind"] == "rule":
            arguments = ["-6", "rule", verb, "priority", str(obj["priority"]), "from", obj["source"],
                         "fwmark", f"{obj['mark']:#x}/0xffffffff", "table", str(obj["table"]), "protocol", "static"]
        else:
            arguments = ["-6", "route", verb, obj["dst"], "dev", self.interface, "table", str(obj["table"]),
                         "proto", "static", "scope", obj["scope"], "metric", str(obj["metric"]), "pref", "medium"]
            if "gateway" in obj:
                arguments.extend(["via", obj["gateway"]])
        self.command(arguments)

    def wait_dad(self, config: dict) -> None:
        deadline = time.monotonic() + DAD_SECONDS
        while True:
            value = self.address_info(config)
            if value is None:
                raise tx.RecoveryError("IPv6 candidate disappeared during DAD")
            flags = set(value.get("flags", []))
            if value.get("dadfailed") or "dadfailed" in flags:
                raise tx.RecoveryError("IPv6 candidate failed duplicate address detection")
            if not value.get("tentative") and "tentative" not in flags:
                return
            if time.monotonic() >= deadline:
                raise tx.RecoveryError("IPv6 candidate DAD did not finish before timeout")
            time.sleep(0.1)

    def verify_route(self, config: dict, allocation: dict, target: str, *, gateway: bool = False) -> dict:
        source = str(ipaddress.ip_interface(config["cidr"]).ip)
        values = self.values(["-6", "route", "get", target, "from", source, "mark", str(allocation["mark"]), "oif", self.interface])
        if len(values) != 1:
            raise tx.RecoveryError("Ambiguous marked IPv6 probe route")
        value = values[0]
        if (value.get("dev") != self.interface or table_id(value.get("table", 254)) != allocation["table"]
                or (not gateway and value.get("gateway") != config["gateway"])
                or (gateway and "gateway" in value)):
            raise tx.RecoveryError("IPv6 probe did not select its candidate gateway/table/interface")
        for key in ("from", "prefsrc", "src"):
            if key in value and str(ipaddress.ip_interface(value[key]).ip) != source:
                raise tx.RecoveryError("IPv6 route selected another source address")
        return value

    def neighbours(self) -> list[dict]:
        return self.values(["-6", "neighbour", "show", "dev", self.interface])

    def verify_gateway(self, config: dict) -> dict:
        values = [value for value in self.neighbours() if value.get("dst") == config["gateway"]]
        allowed = {"REACHABLE", "STALE", "DELAY", "PROBE", "PERMANENT"}
        for value in values:
            state = value.get("state", [])
            state = {state} if isinstance(state, str) else set(state)
            if state & allowed and re.fullmatch(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", value.get("lladdr", "")):
                return value
        raise tx.RecoveryError("IPv6 gateway NDP resolution is absent or failed")


class IPv6Probe:
    def __init__(self, manager: tx.FileTransaction, run_id: str, backend: ProbeBackend,
                 *, connector: TCPConnector | None = None):
        manager._run_id(run_id)
        self.manager, self.run_id, self.backend = manager, run_id, backend
        self.connector = connector or TCPConnector()
        self.path = f"/runs/{run_id}/ipv6-probe.json"

    def save(self, value: dict) -> None:
        self.manager._save(self.path, value)

    def prepare_locked(self, config: dict, before: dict) -> None:
        config = validate_config(config)
        if self.manager.store.snapshot(self.path)["kind"] != "absent":
            raise tx.TransactionError("IPv6 probe journal already exists")
        if self.backend.snapshot() != before:
            raise tx.StalePlan("Network changed before IPv6 probe preparation")
        allocation = self.backend.allocate(self.run_id)
        existing = self.backend.current_address(config)
        reused = existing is not None
        operations = objects(config, allocation, reused=reused)
        if reused and existing != operations[0]:
            raise tx.TransactionError("IPv6 candidate conflicts with a preexisting address")
        value = {"schema_version": 1, "run_id": self.run_id, "config": config, "allocation": allocation,
                 "before": before, "before_neighbours": self.backend.neighbours(), "reused": reused,
                 "phase": "prepared", "operations": [{"object": obj, "owned": not (index == 0 and reused), "phase": "pending"}
                                                         for index, obj in enumerate(operations)], "result": None}
        self.save(value)

    def load(self) -> dict:
        value = self.manager._load(self.path)
        if (value.get("schema_version") != 1 or value.get("run_id") != self.run_id
                or not isinstance(value.get("phase"), str) or value["phase"] not in PHASES or type(value.get("reused")) is not bool
                or not isinstance(value.get("before"), dict) or not isinstance(value.get("before_neighbours"), list)):
            raise tx.TransactionError("Invalid IPv6 probe journal")
        config = validate_config(value["config"])
        allocation = value.get("allocation")
        if not isinstance(allocation, dict) or set(allocation) != {"table", "priority", "mark"}:
            raise tx.TransactionError("Invalid IPv6 probe allocation")
        slot = allocation["table"] - TABLE_BASE if type(allocation["table"]) is int else -1
        if (not 0 <= slot < SLOT_COUNT or allocation != {"table": TABLE_BASE + slot, "priority": PRIORITY_BASE + slot, "mark": MARK_BASE + slot}):
            raise tx.TransactionError("IPv6 probe identifiers do not match their reserved slot")
        expected = objects(config, allocation, reused=value["reused"])
        operations = value.get("operations")
        if not isinstance(operations, list) or len(operations) != len(expected):
            raise tx.TransactionError("Invalid IPv6 probe operations")
        for index, (entry, obj) in enumerate(zip(operations, expected)):
            if (not isinstance(entry, dict) or set(entry) != {"object", "owned", "phase"} or entry["object"] != obj
                    or type(entry["owned"]) is not bool or entry["owned"] != (not (index == 0 and value["reused"]))
                    or entry["phase"] not in ("pending", "intent", "done", "undone")):
                raise tx.TransactionError("Invalid IPv6 probe ownership/intent")
        return value

    def check_link(self, value: dict) -> None:
        if self.backend.link() != value["before"]["link"]:
            raise tx.RecoveryError("IPv6 probe interface identity changed; preserving unrelated state")

    def apply_entry(self, value: dict, entry: dict) -> None:
        self.check_link(value)
        current = self.backend.current(entry["object"], value["config"], value["allocation"])
        if not entry["owned"]:
            if current != entry["object"]:
                raise tx.StalePlan("Reused IPv6 address changed before probing")
            entry["phase"] = "done"
            self.save(value)
            return
        if current is not None:
            raise tx.StalePlan("IPv6 probe identifier was claimed before mutation")
        entry["phase"] = "intent"
        self.save(value)
        self.backend.mutate_probe("add", entry["object"])
        if self.backend.current(entry["object"], value["config"], value["allocation"]) != entry["object"]:
            raise tx.RecoveryError("IPv6 probe mutation did not produce the recorded candidate")
        entry["phase"] = "done"
        self.save(value)

    def run_locked(self) -> dict:
        value = self.load()
        if value["phase"] != "prepared" or self.backend.snapshot() != value["before"]:
            raise tx.StalePlan("IPv6 probe requires its unchanged prepared network")
        if self.backend.allocate(self.run_id) != value["allocation"]:
            raise tx.StalePlan("IPv6 probe allocation changed before its first mutation")
        value["phase"] = "probing"
        self.save(value)
        results, failure = [], None
        try:
            for index, entry in enumerate(value["operations"]):
                self.apply_entry(value, entry)
                if index == 0:
                    self.backend.wait_dad(value["config"])
            self.backend.verify_route(value["config"], value["allocation"], value["config"]["gateway"], gateway=True)
            source = str(ipaddress.ip_interface(value["config"]["cidr"]).ip)
            for target in value["config"]["targets"]:
                self.backend.verify_route(value["config"], value["allocation"], target["address"])
                result = self.connector.connect(self.backend, source, target, value["allocation"]["mark"])
                if (type(result.get("connected")) is not bool or result.get("target") != target["address"] or result.get("port") != target["port"]
                        or result["connected"] and (result.get("source") != source or result.get("mark") != value["allocation"]["mark"])):
                    raise tx.RecoveryError("External check used another IPv6 source or packet mark")
                results.append(result)
            gateway = self.backend.verify_gateway(value["config"])
            if not any(item.get("connected") is True for item in results):
                raise tx.RecoveryError("No external TCP destination was reachable from the candidate IPv6")
            value["result"] = {"passed": True, "dad_passed": True, "route_passed": True,
                               "source": source, "gateway": gateway, "targets": results}
            self.save(value)
        except (tx.TransactionError, OSError, ValueError, subprocess.SubprocessError) as error:
            failure = error
            value["result"] = {"passed": False, "error": str(error), "targets": results}
            self.save(value)
        self.cleanup_locked()
        value = self.load()
        value["phase"] = "failed" if failure else "passed"
        self.save(value)
        if failure:
            raise tx.RecoveryError("IPv6 probe failed before permanent writes: " + str(failure)) from failure
        return copy.deepcopy(value["result"])

    def cleanup_locked(self, *, boot: bool = False) -> None:
        value = self.load()
        if boot:
            value["phase"] = "expired_on_boot"
            self.save(value)
            return
        if value["phase"] in {"passed", "failed", "expired_on_boot"}:
            return
        self.check_link(value)
        value["phase"] = "cleaning"
        self.save(value)
        failures = []
        for entry in reversed(value["operations"]):
            if not entry["owned"] or entry["phase"] in {"pending", "undone"}:
                continue
            try:
                self.check_link(value)
                current = self.backend.current(entry["object"], value["config"], value["allocation"])
                if current is not None:
                    if current != entry["object"]:
                        raise tx.RecoveryError("External IPv6 probe object edit preserved for manual review")
                    self.backend.mutate_probe("delete", entry["object"])
                if self.backend.current(entry["object"], value["config"], value["allocation"]) is not None:
                    raise tx.RecoveryError("IPv6 probe object was not fully removed")
                entry["phase"] = "undone"
                self.save(value)
            except (tx.TransactionError, OSError, ValueError, subprocess.SubprocessError) as error:
                failures.append(str(error))
        try:
            if self.backend.current_routes(value["allocation"]) or self.backend.current_rule(value["config"], value["allocation"]) is not None:
                raise tx.RecoveryError("IPv6 probe table/priority contains external state; preserved")
            current = self.backend.snapshot()
            if current["link"] != value["before"]["link"] or any(obj not in current["objects"] for obj in value["before"]["objects"]):
                raise tx.RecoveryError("Original network inventory was not preserved during IPv6 probing")
        except (tx.TransactionError, OSError, ValueError, subprocess.SubprocessError) as error:
            failures.append(str(error))
        value["phase"] = "recovery_failed" if failures else "failed"
        value["failures"] = failures
        self.save(value)
        if failures:
            raise tx.RecoveryError("; ".join(failures))

    def verify_passed_locked(self) -> None:
        value = self.load()
        if (value["phase"] != "passed" or not isinstance(value["result"], dict) or value["result"].get("passed") is not True
                or any(entry["owned"] and entry["phase"] != "undone" for entry in value["operations"])):
            raise tx.TransactionError("A completed and cleaned IPv6 probe is required before application/acknowledgment")
        result, config = value["result"], value["config"]
        source = str(ipaddress.ip_interface(config["cidr"]).ip)
        targets = result.get("targets")
        if (result.get("dad_passed") is not True or result.get("route_passed") is not True or result.get("source") != source
                or not isinstance(result.get("gateway"), dict) or result["gateway"].get("dst") != config["gateway"]
                or not isinstance(targets, list) or len(targets) != len(config["targets"])):
            raise tx.TransactionError("IPv6 probe success evidence does not match its contract")
        successful = False
        for target, observed in zip(config["targets"], targets):
            if (not isinstance(observed, dict) or type(observed.get("connected")) is not bool
                    or observed.get("target") != target["address"] or observed.get("port") != target["port"]):
                raise tx.TransactionError("Invalid IPv6 TCP success evidence")
            if observed["connected"]:
                if observed.get("source") != source or observed.get("mark") != value["allocation"]["mark"]:
                    raise tx.TransactionError("IPv6 TCP evidence used another source or packet mark")
                successful = True
        if not successful:
            raise tx.TransactionError("IPv6 success evidence has no successful external connection")
