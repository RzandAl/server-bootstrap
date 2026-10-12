"""Fresh-connection proof and terminal-state guards, without host SSH writes."""

import copy
import os
from pathlib import Path
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import recovery as guard
import transaction as tx
import ssh_session as ssh
import test_recovery as fixtures


class FakeProc:
    def __init__(self, uid=1000, gid=1000):
        self.uid, self.gid = uid, gid
        self.records = {
            os.getpid(): self.process_value(os.getpid(), 40, 400, uid, gid, "/usr/bin/python3"),
            40: self.process_value(40, 20, 300, uid, gid, ssh.SESSION_EXECUTABLE),
            20: self.process_value(20, 10, 100, 0, 0, ssh.SESSION_EXECUTABLE),
            10: self.process_value(10, 1, 50, 0, 0, "/usr/sbin/sshd"),
        }
        self.endpoint = ssh.connection("192.0.2.100 43210 198.51.100.20 22")
        self.after_transport = lambda: None

    @staticmethod
    def process_value(pid, ppid, started, uid, gid, executable):
        return {"pid": pid, "ppid": ppid, "start_ticks": started,
                "uids": [uid] * 4, "gids": [gid] * 4, "exe": executable}

    def process(self, pid):
        return copy.deepcopy(self.records[pid])

    def trusted_session(self, value):
        return value["exe"] == ssh.SESSION_EXECUTABLE

    def transport(self, pid):
        if pid != 20:
            raise AssertionError("Must inspect the per-connection root monitor, not its child or listener")
        self.after_transport()
        return 1234, copy.deepcopy(self.endpoint)


class SSHProofTests(unittest.TestCase):
    def setUp(self):
        self.environment = mock.patch.dict(os.environ, {}, clear=True)
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.reader = FakeProc()
        self.inspector = ssh.SSHInspector(self.reader)
        self.account = {"name": "fixture", "uid": 1000, "gid": 1000}

    def test_proof_comes_from_root_monitor_socket_and_authenticated_child(self):
        evidence = self.inspector.capture(self.account)
        self.assertEqual(evidence["monitor_pid"], 20)
        self.assertEqual(evidence["monitor_start_ticks"], 100)
        self.assertEqual(evidence["socket_inode"], 1234)

    def test_missing_environment_hint_still_uses_kernel_proof(self):
        self.assertNotIn("SSH_CONNECTION", os.environ)
        self.assertEqual(self.inspector.capture(self.account)["connection"], self.reader.endpoint)

    def test_matching_hint_is_accepted_but_a_forged_one_is_rejected(self):
        os.environ["SSH_CONNECTION"] = "192.0.2.100 43210 198.51.100.20 22"
        self.inspector.capture(self.account)
        os.environ["SSH_CONNECTION"] = "192.0.2.100 43210 203.0.113.77 22"
        with self.assertRaisesRegex(tx.TransactionError, "kernel connection"):
            self.inspector.capture(self.account)

    def test_fake_hint_without_openssh_ancestry_is_not_a_connection(self):
        self.reader.records[40]["exe"] = "/tmp/sshd-session"
        self.reader.records[20]["exe"] = "/tmp/sshd-session"
        os.environ["SSH_CONNECTION"] = "192.0.2.100 43210 198.51.100.20 22"
        with self.assertRaises(tx.TransactionError):
            self.inspector.capture(self.account, required=False)

    def test_console_is_allowed_for_launch_but_cannot_acknowledge(self):
        self.reader.records[40]["exe"] = "/bin/sh"
        self.reader.records[20]["exe"] = "/bin/sh"
        self.assertIsNone(self.inspector.capture(self.account, required=False))
        with self.assertRaises(tx.TransactionError):
            self.inspector.capture(self.account)

    def test_different_authenticated_uid_or_gid_is_rejected(self):
        for key in ("uids", "gids"):
            with self.subTest(key=key):
                self.reader.records[40][key] = [2000] * 4
                with self.assertRaisesRegex(tx.TransactionError, "authenticated account"):
                    self.inspector.capture(self.account)
                self.reader.records[40][key] = [1000] * 4

    def test_nonroot_monitor_and_missing_privilege_separation_are_rejected(self):
        self.reader.records[20]["uids"] = [1000] * 4
        with self.assertRaises(tx.TransactionError):
            self.inspector.capture(self.account)
        self.reader.records[20]["exe"] = "/bin/sh"
        with self.assertRaises(tx.TransactionError):
            self.inspector.capture(self.account)

    def test_parent_reuse_or_credential_change_during_socket_read_is_rejected(self):
        self.reader.after_transport = lambda: self.reader.records[20].update(start_ticks=101)
        with self.assertRaisesRegex(tx.TransactionError, "ancestry changed"):
            self.inspector.capture(self.account)

    def test_cyclic_ancestry_is_bounded(self):
        self.reader.records[10]["ppid"] = 40
        with self.assertRaisesRegex(tx.TransactionError, "cyclic"):
            self.inspector.capture(self.account)

    def test_process_name_cannot_replace_the_trusted_executable(self):
        self.assertFalse(ssh.ProcReader().trusted_session({"exe": "/tmp/sshd-session"}))

    def test_proc_stat_handles_parentheses_spaces_and_dead_processes(self):
        tail = ["S", "20", *(["0"] * 17), "123", *(["0"] * 10)]
        self.assertEqual(ssh.parse_stat("40 (my ) weird process) " + " ".join(tail)),
                         {"pid": 40, "ppid": 20, "start_ticks": 123})
        tail[0] = "Z"
        with self.assertRaises(tx.TransactionError):
            ssh.parse_stat("40 (dead) " + " ".join(tail))

    @unittest.skipUnless(sys.byteorder == "little", "Fixtures encode Linux little-endian TCP words")
    def test_real_kernel_tcp_encoding_including_ipv4_mapped_ipv6(self):
        self.assertEqual(ssh.tcp_endpoint("146433C6:0016", 4), ("198.51.100.20", 22))
        self.assertEqual(ssh.tcp_endpoint("B80D0120000000000000000020000000:0016", 6), ("2001:db8::20", 22))
        self.assertEqual(ssh.tcp_endpoint("0000000000000000FFFF0000146433C6:0016", 6), ("198.51.100.20", 22))

    def test_invalid_environment_addresses_and_ports_fail_before_use(self):
        for value in ("x 22 y 22", "192.0.2.1 0 198.51.100.20 22", "192.0.2.1 65536 198.51.100.20 22",
                      "192.0.2.1 22 fe80::1%ens3 22", "192.0.2.1 22 198.51.100.20/32 22", "192.0.2.1 22"):
            with self.subTest(value=value), self.assertRaises(tx.TransactionError):
                ssh.connection(value)


class FakeInspector:
    def __init__(self):
        self.identity = ssh.account_identity()
        self.current = None
        self.now = 1000
        self.calls = 0

    def account(self):
        return copy.deepcopy(self.identity)

    def ticks(self):
        return self.now

    def capture(self, account, *, required=True):
        self.calls += 1
        if self.current is None and required:
            raise tx.TransactionError("No live SSH connection")
        return copy.deepcopy(self.current)

    def connect(self, *, started=1001, server="198.51.100.20", pid=200):
        self.current = {"account": self.account(), "monitor_pid": pid, "monitor_start_ticks": started,
                        "socket_inode": 9876, "connection": ssh.connection(f"192.0.2.100 43210 {server} 22")}


class AcknowledgmentTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.RecoveryTests("test_combined_recovery_restores_files_and_addresses_routes")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.manager, self.supervisor, self.run_id = self.fixture.manager, self.fixture.supervisor, self.fixture.run_id
        self.inspector = FakeInspector()
        self.supervisor.session_inspector = self.inspector

    def arm(self):
        self.fixture.arm(ssh_targets=["198.51.100.20"])

    def waiting(self):
        self.arm()
        self.fixture.apply()

    def assert_guarded(self):
        config = self.supervisor.load(self.run_id)
        self.assertTrue(self.supervisor.systemd.active(config["units"]["timer"]))
        self.assertEqual(self.manager._active(), self.run_id)
        self.assertNotEqual(self.manager.status(self.run_id)["phase"], "committed")

    def test_ready_time_is_saved_only_after_complete_file_and_network_application(self):
        self.arm()
        self.assertIsNone(self.supervisor.load(self.run_id)["acknowledgment"]["ready_ticks"])
        self.inspector.now = 2000
        self.fixture.apply()
        value = self.supervisor.load(self.run_id)["acknowledgment"]
        self.assertEqual((value["phase"], value["ready_ticks"]), ("waiting", 2000))

    def test_success_records_proof_before_disarming_and_repeat_is_idempotent(self):
        self.waiting()
        self.inspector.connect()
        healthy = self.fixture.ip.snapshot()
        result = self.supervisor.acknowledge(self.run_id)
        self.assertEqual(result["phase"], "committed")
        value = self.supervisor.load(self.run_id)["acknowledgment"]
        self.assertEqual(value["phase"], "acknowledged")
        self.assertEqual(value["evidence"], self.inspector.current)
        self.assertGreaterEqual(self.inspector.calls, 3)
        self.assertIsNone(self.manager._active())
        self.assertEqual(list(self.fixture.unit_dir.iterdir()), [])
        self.inspector.current = None  # Repeating a terminal result needs no new proof.
        self.supervisor.acknowledge(self.run_id)
        self.supervisor.recover(self.run_id)
        self.assertEqual(self.fixture.ip.snapshot(), healthy)

    def test_old_transport_and_controlmaster_channel_cannot_acknowledge(self):
        self.inspector.connect(started=900)
        self.waiting()
        with self.assertRaisesRegex(tx.TransactionError, "new SSH connection"):
            self.supervisor.acknowledge(self.run_id)
        self.assert_guarded()

    def test_same_clock_tick_is_not_proof_of_a_later_connection(self):
        self.waiting()
        self.inspector.connect(started=1000)
        with self.assertRaises(tx.TransactionError):
            self.supervisor.acknowledge(self.run_id)
        self.assert_guarded()

    def test_new_ssh_to_old_address_cannot_validate_candidate_reachability(self):
        self.waiting()
        self.inspector.connect(server="192.0.2.10")
        with self.assertRaisesRegex(tx.TransactionError, "candidate address"):
            self.supervisor.acknowledge(self.run_id)
        self.assert_guarded()

    def test_changed_invoking_account_and_console_cannot_acknowledge(self):
        self.waiting()
        with self.assertRaises(tx.TransactionError):
            self.supervisor.acknowledge(self.run_id)
        self.inspector.connect()
        self.inspector.identity["uid"] += 1
        with self.assertRaisesRegex(tx.TransactionError, "original invoking account"):
            self.supervisor.acknowledge(self.run_id)
        self.assert_guarded()

    def test_fixture_commit_cannot_bypass_an_ssh_contract(self):
        self.waiting()
        with self.assertRaisesRegex(tx.TransactionError, "cannot bypass"):
            self.supervisor.commit_fixture(self.run_id, verify=lambda: True)
        self.assert_guarded()

    def test_before_application_and_after_rollback_are_not_acknowledgeable(self):
        self.arm()
        self.inspector.connect()
        with self.assertRaises(tx.TransactionError):
            self.supervisor.acknowledge(self.run_id)
        self.supervisor.recover(self.run_id)
        with self.assertRaises(tx.TransactionError):
            self.supervisor.acknowledge(self.run_id)

    def test_invalid_candidate_contract_blocks_target_changes(self):
        for values in (["203.0.113.77"], ["198.51.100.20", "198.51.100.20"], [None], ["fe80::1"], ["127.0.0.1"]):
            with self.subTest(values=values), self.assertRaises(tx.TransactionError):
                self.fixture.arm(ssh_targets=values)
        self.fixture.fixture.assert_originals()

    def test_changed_files_or_reused_gateway_keep_the_guard_armed(self):
        self.waiting()
        self.inspector.connect()
        self.fixture.ip.objects.remove(self.fixture.ip.gateway_route)
        with self.assertRaises(tx.TransactionError):
            self.supervisor.acknowledge(self.run_id)
        self.assert_guarded()
        self.fixture.ip.objects.append(self.fixture.ip.gateway_route)
        self.fixture.fixture.file("/etc/hostname").write_text("external\n")
        with self.assertRaises(tx.TransactionError):
            self.supervisor.acknowledge(self.run_id)
        self.assert_guarded()

    def test_missing_timer_changed_boot_and_both_deadlines_reject_confirmation(self):
        self.waiting()
        self.inspector.connect()
        config = self.supervisor.load(self.run_id)
        for function, value in (("monotonic_ns", config["monotonic_deadline_ns"]), ("time_ns", config["deadline_ns"])):
            with mock.patch.object(guard.time, function, return_value=value), self.assertRaises(tx.TransactionError):
                self.supervisor.acknowledge(self.run_id)
            self.assert_guarded()
        self.fixture.systemd.boot = "other-boot"
        with self.assertRaises(tx.TransactionError):
            self.supervisor.acknowledge(self.run_id)
        self.fixture.systemd.boot = config["generation"]
        self.fixture.systemd.active_units.clear()
        with self.assertRaises(tx.TransactionError):
            self.supervisor.acknowledge(self.run_id)
        self.assertEqual(self.manager._active(), self.run_id)

    def test_deadline_expiring_during_file_health_check_cannot_commit(self):
        self.waiting()
        self.inspector.connect()
        deadline = self.supervisor.load(self.run_id)["monotonic_deadline_ns"]
        current = [deadline - 1]
        snapshot = self.manager.fs.snapshot
        def expire_on_file(path):
            value = snapshot(path)
            current[0] = deadline
            return value
        with mock.patch.object(guard.time, "monotonic_ns", side_effect=lambda: current[0]), \
             mock.patch.object(self.manager.fs, "snapshot", side_effect=expire_on_file):
            with self.assertRaisesRegex(tx.TransactionError, "expired"):
                self.supervisor.acknowledge(self.run_id)
        self.assert_guarded()

    def test_connection_disappearing_before_terminal_commit_keeps_recovery(self):
        self.waiting()
        self.inspector.connect()
        evidence = copy.deepcopy(self.inspector.current)
        with mock.patch.object(self.inspector, "capture", side_effect=[evidence, tx.TransactionError("connection closed")]):
            with self.assertRaises(tx.TransactionError):
                self.supervisor.acknowledge(self.run_id)
        self.assert_guarded()
        self.supervisor.recover(self.run_id)
        self.fixture.fixture.assert_originals()

    def test_cleanup_failure_after_durable_commit_cannot_trigger_undo(self):
        self.waiting()
        self.inspector.connect()
        healthy = self.fixture.ip.snapshot()
        self.fixture.systemd.fail_command = "disable"
        with self.assertRaises(tx.RecoveryError):
            self.supervisor.acknowledge(self.run_id)
        self.assertEqual(self.manager.status(self.run_id)["phase"], "committed")
        self.assertEqual(self.supervisor.load(self.run_id)["acknowledgment"]["evidence"], self.inspector.current)
        self.fixture.systemd.fail_command = None
        self.supervisor.recover(self.run_id)
        self.assertEqual(self.fixture.ip.snapshot(), healthy)

    def test_production_system_root_stays_gated(self):
        with mock.patch.object(self.manager.fs, "root", Path("/")), self.assertRaisesRegex(tx.TransactionError, "Production Base"):
            self.supervisor.acknowledge(self.run_id)

    def test_legacy_recovery_bundle_manifest_can_still_restore_pending_run(self):
        self.arm()
        config = self.supervisor.load(self.run_id)
        config["bundle_sha256"] = {key: value for key, value in config["bundle_sha256"].items() if key in guard.LEGACY_BUNDLE}
        self.manager._save(self.supervisor.path(self.run_id), config)
        self.fixture.apply()
        self.supervisor.recover(self.run_id)
        self.fixture.fixture.assert_originals()
