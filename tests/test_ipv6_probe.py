"""Temporary IPv6 ownership and failure regressions; every target is a fixture."""

import copy
import ipaddress
import json
from pathlib import Path
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import bootstrap
import recovery as guard
import ipv6_probe as probe
import transaction as tx
import network_recovery as net
import test_recovery as fixtures


CONFIG = {"cidr": "2001:db8:2::20/64", "gateway": "fe80::1",
          "targets": [{"address": "2001:db8:ffff::100", "port": 443}, {"address": "2001:db8:ffff::101", "port": 53}]}


class FakeProbeBackend:
    def __init__(self, ip):
        self.ip = ip
        self.interface, self.namespace = ip.interface, None
        self.live, self.calls = [], []
        self.collision = False
        self.dad_error, self.route_error, self.gateway_error = None, None, None
        self.after_mutation = lambda action, obj: None

    def snapshot(self):
        return self.ip.snapshot()

    def link(self):
        return copy.deepcopy(self.ip.link)

    def allocate(self, run_id):
        slot = (int(run_id[-2:], 16) + int(self.collision)) % probe.SLOT_COUNT
        return {"table": probe.TABLE_BASE + slot, "priority": probe.PRIORITY_BASE + slot, "mark": probe.MARK_BASE + slot}

    def current_address(self, config):
        owned = [obj for obj in self.live if obj["kind"] == "address"]
        if owned:
            return copy.deepcopy(owned[0])
        current = [obj for obj in self.ip.objects if obj["kind"] == "address" and obj["family"] == 6
                   and str(ipaddress.ip_interface(obj["cidr"]).ip) == str(ipaddress.ip_interface(config["cidr"]).ip)]
        return {"kind": "address", "cidr": current[0]["cidr"], "mode": "regular"} if current else None

    def current_routes(self, allocation):
        return copy.deepcopy([obj for obj in self.live if obj["kind"] in {"route", "external"}])

    def current_rule(self, config, allocation):
        values = [obj for obj in self.live if obj["kind"] == "rule"]
        return copy.deepcopy(values[0]) if values else None

    def current(self, obj, config, allocation):
        if obj["kind"] == "address":
            return self.current_address(config)
        if obj["kind"] == "rule":
            return self.current_rule(config, allocation)
        matches = [value for value in self.live if value.get("dst") == obj["dst"]]
        return copy.deepcopy(matches[0]) if matches else None

    def mutate_probe(self, action, obj):
        self.calls.append((action, copy.deepcopy(obj)))
        if action == "add":
            self.live.append(copy.deepcopy(obj))
        else:
            self.live.remove(obj)
        self.after_mutation(action, obj)

    def neighbours(self):
        return [{"dst": "fe80::1", "lladdr": "02:00:00:00:00:02", "state": ["REACHABLE"]}]

    def wait_dad(self, config):
        if self.dad_error:
            raise tx.RecoveryError(self.dad_error)

    def verify_route(self, config, allocation, target, **options):
        if self.route_error:
            raise tx.RecoveryError(self.route_error)
        return {"dev": self.interface, "table": allocation["table"]}

    def verify_gateway(self, config):
        if self.gateway_error:
            raise tx.RecoveryError(self.gateway_error)
        return self.neighbours()[0]


class FakeConnector:
    def __init__(self):
        self.calls = []
        self.failures = set()
        self.change = lambda result: result

    def connect(self, backend, source, target, mark):
        self.calls.append((source, copy.deepcopy(target), mark))
        result = {"connected": target["address"] not in self.failures, "source": source,
                  "target": target["address"], "port": target["port"], "mark": mark, "error": None}
        return self.change(result)


class ProbeTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.RecoveryTests("test_combined_recovery_restores_files_and_addresses_routes")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.manager, self.supervisor, self.run_id = self.fixture.manager, self.fixture.supervisor, self.fixture.run_id
        self.backend = FakeProbeBackend(self.fixture.ip)
        self.connector = FakeConnector()
        self.supervisor.probe_backend_factory = lambda *args, **options: self.backend
        self.supervisor.probe_connector = self.connector
        address = net.normalized_object({"kind": "address", "family": 6, "cidr": CONFIG["cidr"]}, "ens3")
        default = net.normalized_object({"kind": "route", "family": 6, "dst": "::/0", "gateway": CONFIG["gateway"]}, "ens3")
        self.fixture.operations.extend([{"action": "add", "object": address}, {"action": "add", "object": default}])

    def arm(self, config=None):
        self.fixture.arm(ipv6_probe=copy.deepcopy(CONFIG if config is None else config))

    def participant(self):
        return self.supervisor.ipv6_probe(self.run_id, self.supervisor.load(self.run_id))

    def test_prepare_is_read_only_and_the_first_mutation_has_durable_intent(self):
        self.arm()
        self.assertEqual(self.backend.calls, [])
        self.fixture.fixture.assert_originals()
        def intent(action, obj):
            if action == "add":
                entry = next(entry for entry in self.participant().load()["operations"] if entry["object"] == obj)
                self.assertEqual(entry["phase"], "intent")
        self.backend.after_mutation = intent
        self.fixture.apply()
        self.assertEqual(self.participant().load()["phase"], "passed")
        self.assertEqual(self.backend.live, [])

    def test_probe_finishes_and_cleans_before_any_file_write(self):
        self.arm()
        calls = self.connector.connect
        def before_files(*arguments):
            self.fixture.fixture.assert_originals()
            return calls(*arguments)
        with mock.patch.object(self.connector, "connect", side_effect=before_files):
            self.fixture.apply()
        self.assertEqual(self.manager.status(self.run_id)["phase"], "applied")
        self.assertTrue(all(call[0] == "2001:db8:2::20" for call in self.connector.calls))

    def test_cleanup_removes_rule_then_routes_then_only_the_owned_address(self):
        self.arm()
        self.fixture.apply()
        deleted = [obj["kind"] for action, obj in self.backend.calls if action == "delete"]
        self.assertEqual(deleted, ["rule", "route", "route", "address"])
        self.assertEqual(self.backend.live, [])

    def test_preexisting_identical_ipv6_is_reused_without_lifetime_changes(self):
        existing = net.normalized_object({"kind": "address", "family": 6, "cidr": CONFIG["cidr"]}, "ens3")
        self.fixture.ip.objects.append(existing)
        self.arm()
        self.fixture.apply()
        self.assertTrue(self.participant().load()["reused"])
        self.assertFalse(any(obj["kind"] == "address" for _, obj in self.backend.calls))
        self.supervisor.recover(self.run_id)
        self.assertIn(existing, self.fixture.ip.objects)

    def test_dad_failure_never_reaches_external_traffic_or_permanent_files(self):
        self.backend.dad_error = "duplicate address detection failed"
        self.arm()
        with self.assertRaises(tx.RecoveryError):
            self.fixture.apply()
        self.fixture.fixture.assert_originals()
        self.assertEqual(self.connector.calls, [])
        self.assertEqual(self.backend.live, [])
        self.supervisor.recover(self.run_id)

    def test_unreachable_external_targets_stop_application_and_clean(self):
        self.connector.failures = {target["address"] for target in CONFIG["targets"]}
        self.arm()
        with self.assertRaisesRegex(tx.RecoveryError, "No external TCP"):
            self.fixture.apply()
        self.fixture.fixture.assert_originals()
        self.assertEqual(self.backend.live, [])
        self.assertFalse(self.participant().load()["result"]["passed"])
        self.supervisor.recover(self.run_id)

    def test_one_successful_destination_is_enough_without_disabling_ipv6(self):
        self.connector.failures = {CONFIG["targets"][0]["address"]}
        self.arm()
        self.fixture.apply()
        self.assertEqual(self.participant().load()["phase"], "passed")
        self.assertEqual(len(self.connector.calls), 2)

    def rejected_identity(self, field, value):
        self.connector.change = lambda result: {**result, field: value}
        self.arm()
        with self.assertRaises(tx.RecoveryError):
            self.fixture.apply()
        self.fixture.fixture.assert_originals()
        self.supervisor.recover(self.run_id)

    def test_an_old_working_source_cannot_false_pass(self):
        self.rejected_identity("source", "2001:db8:1::10")

    def test_a_wrong_packet_mark_cannot_false_pass(self):
        self.rejected_identity("mark", 1)

    def test_wrong_route_or_unresolved_gateway_never_commits(self):
        self.backend.route_error = "wrong table/interface"
        self.arm()
        with self.assertRaises(tx.RecoveryError):
            self.fixture.apply()
        self.fixture.fixture.assert_originals()
        self.assertEqual(self.backend.live, [])
        self.supervisor.recover(self.run_id)

    def test_gateway_resolution_is_checked_even_after_a_tcp_success(self):
        self.backend.gateway_error = "gateway NDP failed"
        self.arm()
        with self.assertRaises(tx.RecoveryError):
            self.fixture.apply()
        self.fixture.fixture.assert_originals()
        self.assertEqual(self.backend.live, [])
        self.supervisor.recover(self.run_id)

    def test_policy_collision_after_arming_stops_before_address_addition(self):
        self.arm()
        self.backend.collision = True
        with self.assertRaises(tx.StalePlan):
            self.fixture.apply()
        self.assertEqual(self.backend.calls, [])
        self.fixture.fixture.assert_originals()
        self.supervisor.recover(self.run_id)

    def test_writer_death_after_address_intent_is_recovered_independently(self):
        self.arm()
        self.backend.after_mutation = lambda action, obj: (_ for _ in ()).throw(KeyboardInterrupt()) if action == "add" else None
        with self.assertRaises(KeyboardInterrupt):
            self.fixture.apply()
        self.assertEqual(self.participant().load()["operations"][0]["phase"], "intent")
        self.backend.after_mutation = lambda *args: None
        self.supervisor.recover(self.run_id)
        self.assertEqual(self.backend.live, [])
        self.fixture.fixture.assert_originals()

    def test_external_rule_edit_is_preserved_and_blocks_another_run(self):
        self.arm()
        self.connector.change = lambda result: (_ for _ in ()).throw(KeyboardInterrupt())
        with self.assertRaises(KeyboardInterrupt):
            self.fixture.apply()
        rule = next(obj for obj in self.backend.live if obj["kind"] == "rule")
        rule["mark"] += 1
        with self.assertRaises(tx.RecoveryError):
            self.supervisor.recover(self.run_id)
        self.assertIn(rule, self.backend.live)
        self.assertEqual(self.manager._active(), self.run_id)
        self.fixture.fixture.assert_originals()

    def test_replacement_interface_is_never_touched_by_probe_cleanup(self):
        self.arm()
        self.backend.after_mutation = lambda action, obj: (_ for _ in ()).throw(KeyboardInterrupt()) if action == "add" else None
        with self.assertRaises(KeyboardInterrupt):
            self.fixture.apply()
        count = len(self.backend.calls)
        self.fixture.ip.link["ifindex"] += 1
        with self.assertRaises(tx.RecoveryError):
            self.supervisor.recover(self.run_id)
        self.assertEqual(len(self.backend.calls), count)

    def test_boot_expiration_does_not_replay_old_probe_identifiers(self):
        self.arm()
        self.backend.after_mutation = lambda action, obj: (_ for _ in ()).throw(KeyboardInterrupt()) if action == "add" else None
        with self.assertRaises(KeyboardInterrupt):
            self.fixture.apply()
        count = len(self.backend.calls)
        self.fixture.systemd.boot = "new-boot"
        self.supervisor.recover(self.run_id, boot=True)
        self.assertEqual(len(self.backend.calls), count)
        self.assertEqual(self.participant().load()["phase"], "expired_on_boot")

    def test_passed_probe_cleanup_never_removes_the_later_permanent_address(self):
        self.arm()
        self.fixture.apply()
        count = len(self.backend.calls)
        self.participant().cleanup_locked()
        self.assertEqual(len(self.backend.calls), count)
        self.assertIsNotNone(self.backend.current_address(CONFIG))
        self.supervisor.recover(self.run_id)
        self.assertEqual(len(self.backend.calls), count)

    def test_corrupted_probe_evidence_cannot_commit_an_applied_run(self):
        self.arm()
        self.fixture.apply()
        participant = self.participant()
        value = participant.load()
        value["result"]["source"] = "2001:db8:1::10"
        participant.save(value)
        with self.assertRaises(tx.TransactionError):
            self.supervisor.commit_fixture(self.run_id, verify=lambda: True)
        self.assertEqual(self.manager._active(), self.run_id)
        self.supervisor.recover(self.run_id)

    def test_candidate_mismatch_between_probe_and_permanent_plan_is_rejected(self):
        config = {**CONFIG, "cidr": "2001:db8:3::20/64"}
        with self.assertRaisesRegex(tx.TransactionError, "planned permanent"):
            self.arm(config)
        self.fixture.fixture.assert_originals()


class ProbeParserTests(unittest.TestCase):
    def test_link_identity_uses_link_inventory_when_ipv6_address_output_omits_mac(self):
        backend = probe.ProbeBackend("ens3")
        identity = {"ifindex": 12, "ifname": "ens3", "address": "02:00:00:00:00:01", "mtu": 1500}
        def inventory(arguments):
            if "link" in arguments:
                return json.dumps([{**identity, "flags": ["UP", "LOWER_UP"]}])
            return json.dumps([{"ifindex": 12, "ifname": "ens3", "flags": ["UP"], "addr_info": []}])
        with mock.patch.object(backend, "command", side_effect=inventory):
            self.assertEqual(backend.link(), identity)

    def test_incomplete_link_identity_is_a_recovery_error(self):
        backend = probe.ProbeBackend("ens3")
        with mock.patch.object(backend, "command", return_value=json.dumps([{"ifindex": 12, "ifname": "ens3", "flags": ["UP"]}])):
            with self.assertRaisesRegex(tx.RecoveryError, "identity is incomplete"):
                backend.link()

    def test_read_only_plan_discloses_targets_and_ipv4_only_has_no_probe(self):
        values = {"schema_version": 1, "hostname": "fixture", "interface": "ens3", "ipv4_cidr": "192.0.2.10/32",
                  "ipv4_gateway": "198.51.100.1", "ipv6_enabled": True, "ipv6_cidr": CONFIG["cidr"],
                  "ipv6_gateway": CONFIG["gateway"], "motd": False}
        with mock.patch.object(bootstrap.subprocess, "run") as execute:
            plan = bootstrap.build_plan(bootstrap.Profile.from_dict(values, current_user="fixture"))
            self.assertEqual(plan["ipv6_probe"]["targets"], [{"address": addr, "port": port} for addr, port in bootstrap.IPV6_PROBE_TARGETS])
            self.assertIn("after confirmation", bootstrap.format_plan(plan))
            values.update(ipv6_enabled=False, ipv6_cidr=None, ipv6_gateway=None)
            self.assertIsNone(bootstrap.build_plan(bootstrap.Profile.from_dict(values, current_user="fixture"))["ipv6_probe"])
            execute.assert_not_called()

    def test_invalid_prefix_gateway_and_endpoint_values_are_rejected(self):
        invalid = [
            {**CONFIG, "cidr": "22a12:db8::2/64"}, {**CONFIG, "cidr": "2001:db8:2::20/0"},
            {**CONFIG, "gateway": "fe80::1%ens3"}, {**CONFIG, "gateway": "2001:db8:3::1"},
            {**CONFIG, "targets": [{"address": "::1", "port": 443}]},
            {**CONFIG, "targets": [{"address": "2001:db8:2::40", "port": 443}]},
            {**CONFIG, "targets": [{"address": "2001:db8:ffff::100", "port": True}]},
            {**CONFIG, "targets": [CONFIG["targets"][0]] * 2}, {**CONFIG, "command": "echo unsafe"},
        ]
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(tx.TransactionError):
                probe.validate_config(value)

    def test_global_in_prefix_gateway_and_link_local_gateway_are_supported(self):
        for gateway in ("2001:db8:2::1", "fe80::1"):
            self.assertEqual(probe.validate_config({**CONFIG, "gateway": gateway})["gateway"], gateway)

    def test_probe_address_has_no_connected_route_and_is_not_preferred(self):
        backend = probe.ProbeBackend("ens3")
        calls = []
        with mock.patch.object(backend, "command", side_effect=lambda args: calls.append(args) or ""):
            backend.mutate_probe("add", {"kind": "address", "cidr": CONFIG["cidr"], "mode": "probe"})
        self.assertIn("noprefixroute", calls[0])
        self.assertEqual(calls[0][calls[0].index("preferred_lft") + 1], "0")
        self.assertNotIn("nodad", calls[0])

    def test_ipv6_host_route_without_scope_matches_its_owned_kernel_object(self):
        backend = probe.ProbeBackend("ens3")
        allocation = {"table": probe.TABLE_BASE, "priority": probe.PRIORITY_BASE, "mark": probe.MARK_BASE}
        expected = probe.objects(CONFIG, allocation, reused=False)[1]
        raw = {"dst": CONFIG["gateway"], "dev": "ens3", "table": allocation["table"],
               "protocol": "static", "prefsrc": "2001:db8:2::20", "metric": 1024, "flags": [], "pref": "medium"}
        with mock.patch.object(backend, "all_routes", return_value=[raw]):
            self.assertEqual(backend.current(expected, CONFIG, allocation), expected)
        with mock.patch.object(backend, "all_routes", return_value=[{**raw, "nhid": 99}]):
            self.assertEqual(backend.current(expected, CONFIG, allocation)["kind"], "external")

    def test_allocator_skips_used_tables_priorities_and_mark_masks(self):
        backend = probe.ProbeBackend("ens3")
        routes = [{"table": probe.TABLE_BASE}]
        rules = [{"priority": probe.PRIORITY_BASE + 1, "table": "main"},
                 {"priority": 123, "fwmark": hex(probe.MARK_BASE + 2), "table": "main"}]
        with mock.patch.object(backend, "all_routes", return_value=routes), mock.patch.object(backend, "rules", return_value=rules):
            value = backend.allocate("0" * 32)
        self.assertEqual(value["table"], probe.TABLE_BASE + 3)

    def test_fully_overlapping_packet_mark_rule_blocks_allocation(self):
        backend = probe.ProbeBackend("ens3")
        with mock.patch.object(backend, "all_routes", return_value=[]), \
             mock.patch.object(backend, "rules", return_value=[{"priority": 123, "fwmark": "0x0", "fwmask": "0x0", "table": "main"}]):
            with self.assertRaises(tx.TransactionError):
                backend.allocate("0" * 32)

    def test_route_lookup_must_use_selected_gateway_table_and_interface(self):
        backend = probe.ProbeBackend("ens3")
        allocation = {"table": probe.TABLE_BASE, "priority": probe.PRIORITY_BASE, "mark": probe.MARK_BASE}
        route = {"table": probe.TABLE_BASE, "gateway": CONFIG["gateway"], "dev": "ens3",
                 "from": "2001:db8:2::20", "prefsrc": "2001:db8:2::20"}
        with mock.patch.object(backend, "values", return_value=[route]):
            backend.verify_route(CONFIG, allocation, CONFIG["targets"][0]["address"])
        for key, value in (("table", 254), ("gateway", "fe80::2"), ("dev", "eth1"),
                           ("from", "2001:db8:1::10"), ("prefsrc", "2001:db8:1::10")):
            with mock.patch.object(backend, "values", return_value=[{**route, key: value}]), self.assertRaises(tx.RecoveryError):
                backend.verify_route(CONFIG, allocation, CONFIG["targets"][0]["address"])

    def test_gateway_ndp_requires_usable_state_and_hardware_address(self):
        backend = probe.ProbeBackend("ens3")
        for state in (["INCOMPLETE"], ["FAILED"], []):
            with mock.patch.object(backend, "neighbours", return_value=[{"dst": "fe80::1", "state": state}]), self.assertRaises(tx.RecoveryError):
                backend.verify_gateway(CONFIG)

    def test_tcp_subprocess_is_marked_bound_and_has_no_shell(self):
        connector = probe.TCPConnector()
        backend = probe.ProbeBackend("ens3")
        result = {"connected": True, "source": "2001:db8:2::20", "target": CONFIG["targets"][0]["address"],
                  "port": 443, "mark": probe.MARK_BASE, "error": None}
        with mock.patch.object(probe.subprocess, "run", return_value=mock.Mock(returncode=0, stdout=json.dumps(result), stderr="")) as execute:
            connector.connect(backend, result["source"], CONFIG["targets"][0], probe.MARK_BASE)
        args, options = execute.call_args
        self.assertNotIn("shell", options)
        payload = json.loads(args[0][-1])
        self.assertEqual((payload["source"], payload["interface"], payload["mark"]), (result["source"], "ens3", probe.MARK_BASE))
        self.assertIn("SO_BINDTODEVICE", probe.TCP_CODE)
        self.assertIn("SO_MARK", probe.TCP_CODE)
