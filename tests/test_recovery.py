"""Supervisor and owned-network-delta regressions; no host service/network writes."""

import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import transaction as tx
import network_recovery as net
import recovery as guard
import test_transaction as fixtures


class FakeIP:
    def __init__(self):
        self.interface = "ens3"
        self.namespace = None
        self.link = {"ifindex": 2, "ifname": "ens3", "address": "02:00:00:00:00:01", "mtu": 1500}
        self.old_address = net.normalized_object({"kind": "address", "family": 4, "cidr": "192.0.2.10/32"}, "ens3")
        self.gateway_route = net.normalized_object({"kind": "route", "family": 4, "dst": "198.51.100.1/32", "protocol": "static", "scope": "link"}, "ens3")
        self.old_default = net.normalized_object({"kind": "route", "family": 4, "dst": "0.0.0.0/0", "gateway": "198.51.100.1", "src": "192.0.2.10"}, "ens3")
        self.objects = [self.old_address, self.gateway_route, self.old_default]
        self.calls = []
        self.fail_once = None

    def snapshot(self, **options):
        return copy.deepcopy({"link": self.link, "objects": sorted(self.objects, key=lambda obj: json.dumps(obj, sort_keys=True)), "pending": []})

    def settled(self):
        return self.snapshot()

    def mutate(self, action, value):
        self.calls.append((action, copy.deepcopy(value)))
        if self.fail_once == len(self.calls):
            self.fail_once = None
            raise tx.RecoveryError("injected ip failure")
        if action == "add":
            if any(net.identity(obj) == net.identity(value) for obj in self.objects):
                raise tx.RecoveryError("Object exists")
            self.objects.append(copy.deepcopy(value))
        else:
            self.objects.remove(value)


class FakeSystemd:
    def __init__(self):
        self.calls = []
        self.active_units = set()
        self.boot = "boot-one:12345"
        self.fail_command = None

    def generation(self):
        return self.boot

    def command(self, *arguments, **options):
        self.calls.append(arguments)
        if self.fail_command == arguments[0]:
            raise tx.RecoveryError("injected systemd failure")
        if arguments[0] == "enable" and "--now" in arguments:
            self.active_units.add(arguments[-1])
        if arguments[0] in {"disable", "stop"}:
            self.active_units.discard(arguments[-1])
        return ""

    def active(self, unit):
        return unit in self.active_units


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.TransactionTests("test_prepare_saves_only_changed_originals_without_target_writes")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.manager, self.plan = self.fixture.manager, self.fixture.plan
        self.unit_dir = self.fixture.directory / "units"
        self.unit_dir.mkdir()
        self.ip, self.systemd = FakeIP(), FakeSystemd()
        self.before = self.ip.snapshot()
        self.supervisor = guard.RecoverySupervisor(self.manager, systemd=self.systemd, unit_dir=self.unit_dir,
                                                    backend_factory=lambda *args, **kwargs: self.ip)
        self.run_id = self.fixture.prepare()
        self.new_address = net.normalized_object({"kind": "address", "family": 4, "cidr": "198.51.100.20/32"}, "ens3")
        self.new_default = {**self.ip.old_default, "src": "198.51.100.20"}
        self.operations = [{"action": "add", "object": self.new_address},
                           {"action": "add", "object": self.ip.gateway_route},
                           {"action": "delete", "object": self.ip.old_default},
                           {"action": "add", "object": self.new_default},
                           {"action": "delete", "object": self.ip.old_address}]

    def arm(self, **options):
        self.supervisor.arm(self.run_id, self.plan, interface="ens3", operations=self.operations, **options)

    def apply(self):
        self.supervisor.start(self.run_id)
        self.supervisor.apply_fixture(self.run_id)

    def journal(self):
        return self.supervisor.network(self.run_id, self.supervisor.load(self.run_id))

    def test_arm_creates_private_bundle_before_starting_persistent_guard(self):
        self.arm()
        self.fixture.assert_originals()
        self.assertEqual(self.ip.calls, [])
        config = self.supervisor.load(self.run_id)
        self.assertEqual(config["phase"], "armed")
        self.assertTrue(self.systemd.active(config["units"]["timer"]))
        self.assertIn(("enable", config["units"]["boot"]), self.systemd.calls)
        self.assertIn(("enable", "--now", config["units"]["timer"]), self.systemd.calls)
        for path in (self.manager.state_dir / "runs" / self.run_id / "worker").iterdir():
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        timer = (self.unit_dir / config["units"]["timer"]).read_text()
        self.assertIn("Persistent=yes", timer)
        self.assertIn("OnActiveSec=300s", timer)
        self.assertIn("OnCalendar=", timer)

    def test_combined_recovery_restores_files_and_addresses_routes(self):
        self.arm()
        self.apply()
        self.assertNotEqual(self.ip.snapshot(), self.before)
        self.supervisor.recover(self.run_id)
        self.fixture.assert_originals()
        self.assertEqual(self.ip.snapshot(), self.before)
        self.assertFalse((self.manager.state_dir / "active.json").exists())
        self.assertEqual(list(self.unit_dir.iterdir()), [])

    def test_reused_route_is_never_claimed_or_deleted(self):
        self.arm()
        entries = self.journal().load()["operations"]
        self.assertFalse(entries[1]["owned"])
        self.apply()
        self.supervisor.recover(self.run_id)
        self.assertFalse(any(obj == self.ip.gateway_route for _, obj in self.ip.calls))

    def test_unrelated_network_addition_survives_recovery(self):
        self.arm()
        self.apply()
        unrelated = net.normalized_object({"kind": "route", "family": 4, "dst": "203.0.113.0/24", "scope": "link", "metric": 42}, "ens3")
        self.ip.objects.append(unrelated)
        self.supervisor.recover(self.run_id)
        self.assertIn(unrelated, self.ip.objects)

    def test_partial_network_failure_leaves_guard_and_recovers_both_layers(self):
        self.arm()
        self.ip.fail_once = 3
        with self.assertRaises(tx.RecoveryError):
            self.apply()
        self.assertTrue((self.manager.state_dir / "active.json").exists())
        self.supervisor.recover(self.run_id)
        self.fixture.assert_originals()
        self.assertEqual(self.ip.snapshot(), self.before)

    def test_write_intent_recovers_crash_immediately_after_network_mutation(self):
        self.arm()
        journal = self.journal()
        data = journal.load()
        data["phase"] = "applying"
        data["operations"][0]["phase"] = "intent"
        self.manager._save(journal.path, data)
        self.ip.mutate("add", self.new_address)
        self.supervisor.recover(self.run_id)
        self.assertEqual(self.ip.snapshot(), self.before)

    def test_network_intent_before_mutation_does_not_delete_reused_state(self):
        self.arm()
        journal = self.journal()
        data = journal.load()
        data["phase"] = "applying"
        data["operations"][0]["phase"] = "intent"
        self.manager._save(journal.path, data)
        self.supervisor.recover(self.run_id)
        self.assertEqual(self.ip.calls, [])

    def test_file_conflict_still_restores_network_and_keeps_run_blocked(self):
        self.arm()
        self.apply()
        self.fixture.file("/etc/hostname").write_text("external\n")
        with self.assertRaises(tx.RecoveryError):
            self.supervisor.recover(self.run_id)
        self.assertEqual(self.ip.snapshot(), self.before)
        self.assertEqual(self.fixture.file("/etc/hostname").read_text(), "external\n")
        self.assertEqual(self.manager.status(self.run_id)["phase"], "recovery_failed")
        self.assertTrue((self.manager.state_dir / "active.json").exists())

    def test_network_conflict_preserves_external_object_and_restores_files(self):
        self.arm()
        self.apply()
        self.ip.objects.remove(self.new_address)
        external = {**self.new_address, "cidr": "198.51.100.20/24"}
        self.ip.objects.append(external)
        with self.assertRaises(tx.RecoveryError):
            self.supervisor.recover(self.run_id)
        self.fixture.assert_originals()
        self.assertIn(external, self.ip.objects)
        self.assertTrue((self.manager.state_dir / "active.json").exists())

    def test_replaced_interface_is_not_modified_during_recovery(self):
        self.arm()
        self.apply()
        self.ip.link["ifindex"] = 999
        calls = len(self.ip.calls)
        with self.assertRaises(tx.RecoveryError):
            self.supervisor.recover(self.run_id)
        self.assertEqual(len(self.ip.calls), calls)
        self.fixture.assert_originals()

    def test_bare_file_recovery_and_commit_cannot_bypass_network_participant(self):
        self.arm()
        self.apply()
        with self.assertRaises(tx.RecoveryError):
            self.manager.recover(self.run_id)
        with self.assertRaises(tx.TransactionError):
            self.manager.commit(self.run_id)
        self.assertTrue((self.manager.state_dir / "active.json").exists())

    def test_failed_timer_start_never_permits_writes(self):
        self.systemd.fail_command = "enable"
        with self.assertRaises(tx.RecoveryError):
            self.arm()
        with self.assertRaises(tx.TransactionError):
            self.supervisor.start(self.run_id)
        self.fixture.assert_originals()
        self.assertEqual(self.ip.calls, [])
        self.systemd.fail_command = None
        self.supervisor.recover(self.run_id)

    def test_existing_unit_is_preserved_and_blocks_arming(self):
        name = guard.unit_names(self.run_id)["apply"]
        path = self.unit_dir / name
        path.write_text("external unit\n")
        with self.assertRaises(tx.TransactionError):
            self.arm()
        self.assertEqual(path.read_text(), "external unit\n")
        self.assertFalse(self.manager.status(self.run_id).get("supervised", False))

    def test_corrupt_protected_worker_blocks_start(self):
        self.arm()
        path = self.manager.state_dir / "runs" / self.run_id / "worker/transaction.py"
        path.write_text("corrupt\n")
        with self.assertRaises(tx.TransactionError):
            self.supervisor.start(self.run_id)
        self.fixture.assert_originals()
        self.supervisor.recover(self.run_id)  # Trusted checkout can recover despite a damaged bundle.

    def test_expired_acknowledgment_cannot_disarm_timer(self):
        self.arm()
        self.apply()
        config = self.supervisor.load(self.run_id)
        with mock.patch.object(guard.time, "monotonic_ns", return_value=config["monotonic_deadline_ns"] + 1):
            with self.assertRaises(tx.TransactionError):
                self.supervisor.commit_fixture(self.run_id, verify=lambda: True)
        self.assertTrue(self.systemd.active(config["units"]["timer"]))

    def test_failed_health_check_keeps_recovery_armed(self):
        self.arm()
        self.apply()
        with self.assertRaises(tx.TransactionError):
            self.supervisor.commit_fixture(self.run_id, verify=lambda: False)
        self.assertTrue((self.manager.state_dir / "active.json").exists())

    def test_healthy_fixture_commit_disarms_and_late_timer_cannot_undo(self):
        self.arm()
        self.apply()
        healthy = self.ip.snapshot()
        self.supervisor.commit_fixture(self.run_id, verify=lambda: True)
        self.assertEqual(list(self.unit_dir.iterdir()), [])
        self.supervisor.recover(self.run_id)
        self.assertEqual(self.ip.snapshot(), healthy)
        self.assertEqual(self.fixture.file("/etc/hostname").read_text(), "new-host\n")

    def test_boot_recovery_restores_files_without_replaying_old_interface_indices(self):
        self.arm()
        self.apply()
        self.systemd.boot = "new-boot:99999"
        self.ip.objects = []
        self.ip.link["ifindex"] = 300
        calls = len(self.ip.calls)
        self.supervisor.recover(self.run_id, boot=True)
        self.fixture.assert_originals()
        self.assertEqual(len(self.ip.calls), calls)
        self.assertEqual(self.journal().load()["phase"], "expired_on_boot")
        self.assertNotIn(("disable", "--now", guard.unit_names(self.run_id)["boot"]), self.systemd.calls)

    def test_boot_operation_is_rejected_in_the_same_boot(self):
        self.arm()
        with self.assertRaises(tx.TransactionError):
            self.supervisor.recover(self.run_id, boot=True)
        self.assertEqual(self.manager.status(self.run_id)["phase"], "prepared")

    def test_cleanup_preserves_external_unit_edit(self):
        self.arm()
        name = guard.unit_names(self.run_id)["apply"]
        path = self.unit_dir / name
        path.write_text("external edit\n")
        with self.assertRaises(tx.RecoveryError):
            self.supervisor.recover(self.run_id)
        self.assertEqual(path.read_text(), "external edit\n")
        self.fixture.assert_originals()

    def test_restore_candidate_addresses_before_originals_then_routes(self):
        self.arm()
        self.apply()
        start = len(self.ip.calls)
        self.supervisor.recover(self.run_id)
        restoration = self.ip.calls[start:]
        self.assertEqual(restoration[0], ("delete", self.new_address))
        self.assertEqual(restoration[1], ("add", self.ip.old_address))
        self.assertTrue(all(obj["kind"] == "route" for _, obj in restoration[2:]))

    def test_missing_baseline_route_prevents_false_recovery_success(self):
        self.arm()
        self.apply()
        self.ip.objects.remove(self.ip.gateway_route)
        with self.assertRaisesRegex(tx.RecoveryError, "fully restored"):
            self.supervisor.recover(self.run_id)
        self.assertTrue((self.manager.state_dir / "active.json").exists())

    def test_unit_paths_and_timeouts_reject_systemd_injection(self):
        for path in ("/tmp/a%h", "/tmp/a b", "/tmp/a\nExecStart=/bin/false"):
            with self.subTest(path=path), self.assertRaises(tx.TransactionError):
                guard.unit_texts(self.run_id, Path(path), Path("/var/lib/state"), 300, 2_000_000_000)
        for timeout in (0, 4, True, 1801):
            with self.subTest(timeout=timeout), self.assertRaises(tx.TransactionError):
                self.arm(timeout=timeout)

    @unittest.skipUnless(shutil.which("systemd-analyze"), "systemd-analyze is installed in Debian CI")
    def test_real_systemd_parser_accepts_generated_units(self):
        self.arm()
        result = subprocess.run([shutil.which("systemd-analyze"), "verify", "--man=no", *map(str, self.unit_dir.iterdir())],
                                capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)


class IPNormalizationTests(unittest.TestCase):
    def test_ipv6_metric_and_preference_match_kernel_defaults(self):
        obj = net.normalized_object({"kind": "route", "family": 6, "dst": "::/0", "gateway": "fe80::1"}, "ens3")
        self.assertEqual(obj["metric"], 1024)
        self.assertEqual(obj["pref"], "medium")

    def test_unsupported_family_flags_protocol_and_routes_are_rejected(self):
        objects = [{"kind": "address", "family": 6, "cidr": "22a12:1::2/64"},
                   {"kind": "address", "family": 4, "cidr": "192.0.2.1/32", "arbitrary": "x"},
                   {"kind": "route", "family": 4, "dst": "::/0"},
                   {"kind": "route", "family": 6, "dst": "::/0", "protocol": "ra"},
                   {"kind": "route", "family": 4, "dst": "0.0.0.0/0", "onlink": "true"}]
        for obj in objects:
            with self.subTest(obj=obj), self.assertRaises(ValueError):
                net.normalized_object(obj, "ens3")

    def test_ip_commands_are_argument_arrays_without_replace_or_flush(self):
        backend = net.IPBackend("ens3")
        commands = []
        with mock.patch.object(backend, "command", side_effect=lambda args: commands.append(args)):
            backend.mutate("add", {"kind": "address", "family": 4, "cidr": "192.0.2.2/32", "peer": "198.51.100.1/32"})
            backend.mutate("delete", {"kind": "route", "family": 6, "dst": "::/0", "gateway": "fe80::1", "protocol": "static"})
        self.assertEqual(commands[0][:6], ["-4", "address", "add", "192.0.2.2/32", "peer", "198.51.100.1/32"])
        self.assertNotIn("flush", sum(commands, []))
        self.assertNotIn("replace", sum(commands, []))


if __name__ == "__main__":
    unittest.main()
