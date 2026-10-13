"""Base lifecycle regressions with isolated files and typed fake backends."""

import copy
from dataclasses import replace
import json
import os
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest import mock

import recovery as guard
import transaction as tx
import bootstrap
import preflight
import test_preflight as host_fixtures
import test_recovery as net_fixtures

base, pkg = guard.base, guard.pkg


class FakePackages:
    def __init__(self):
        self.names = set(bootstrap.BASE_PACKAGES) - {"ccze"}
        self.audit = ""
        self.calls = []
        self.on_run = lambda operation, names: None
        self.failed = None
        self.partial = False

    def inspect(self):
        return pkg.inventory("".join(f"{name}\t1.0\tii \n" for name in sorted(self.names)), self.audit)

    def run(self, operation, names):
        self.calls.append((operation, list(names)))
        self.on_run(operation, names)
        if operation == "install" and (self.failed != operation or self.partial):
            self.names.update(names)
        return {"returncode": 100 if self.failed == operation else 0, "output": "fixture", "truncated": False}


class FakeHostname:
    def __init__(self):
        self.value = "oldhost"
        self.namespace = {"device": 1, "inode": 2}
        self.calls = []

    def snapshot(self):
        return {"hostname": self.value, "namespace": copy.deepcopy(self.namespace)}

    def set(self, hostname):
        self.calls.append(hostname)
        self.value = hostname


class FakeInspector:
    def __init__(self):
        self.identity = {"name": "razis", "uid": os.getuid(), "gid": os.getgid()}
        self.now, self.started = 100, 200

    def account(self):
        return copy.deepcopy(self.identity)

    def ticks(self):
        return self.now

    def capture(self, account, *, required=True):
        if not required:
            return None
        return {"account": account, "monitor_pid": 20, "monitor_start_ticks": self.started, "socket_inode": 1234,
                "connection": {"client_address": "192.0.2.100", "client_port": 43210,
                               "server_address": "198.51.100.20", "server_port": 22}}


class BaseTests(unittest.TestCase):
    def setUp(self):
        self.environment = mock.patch.dict(os.environ, {}, clear=True)
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.fixture = host_fixtures.HostPlanTests("test_full_plan_preserves_target_bytes_and_reports_exact_candidates")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.root = self.fixture.root
        self.manager = tx.FileTransaction(root=self.root, state_dir=self.root / "state")
        self.units = self.root / "units"
        self.units.mkdir()
        self.ip, self.systemd = net_fixtures.FakeIP(), net_fixtures.FakeSystemd()
        self.packages, self.hostname, self.inspector = FakePackages(), FakeHostname(), FakeInspector()
        self.before = self.ip.snapshot()
        values = {**host_fixtures.EXAMPLE, "ipv4_cidr": "198.51.100.20/32", "ipv6_enabled": False,
                  "ipv6_cidr": None, "ipv6_gateway": None, "motd": False}
        self.profile = bootstrap.Profile.from_dict(values, current_user="razis")
        self.account = SimpleNamespace(pw_name="razis", pw_uid=os.getuid(), pw_gid=os.getgid(), pw_dir="/home/razis", pw_shell="/bin/bash")
        self.supervisor = guard.RecoverySupervisor(self.manager, systemd=self.systemd, unit_dir=self.units,
            backend_factory=lambda *a, **k: self.ip, session_inspector=self.inspector,
            package_backend_factory=lambda *a, **k: self.packages, hostname_backend_factory=lambda *a, **k: self.hostname)

    def report(self):
        class OwnedView(host_fixtures.FixtureView):
            def file(self, path):
                state = super().file(path)
                if path.startswith("/home/razis/") and state.kind != "absent":
                    state = replace(state, uid=os.getuid(), gid=os.getgid())
                    self.files[path] = state
                return state
        view = OwnedView(self.root)
        view.packages.update(self.packages.names)
        current = next(obj for obj in self.ip.objects if obj["kind"] == "address" and obj["family"] == 4)
        interface = current["cidr"].split("/")
        view.addresses[0]["addr_info"][0].update(local=interface[0], prefixlen=int(interface[1]))
        report = preflight.prepare_host_plan(self.profile, self.account, bootstrap.build_plan(self.profile),
                                             bootstrap.merge_profile_timezone, view=view)
        self.assertEqual(report["blockers"], [])
        # These are fake target roots: use their actual current UID/GID and
        # fingerprints so the same lifecycle tests work without root as well.
        for path in report["watched_files"]:
            report["watched_files"][path] = tx.fingerprint(self.manager.fs.snapshot(path))
        for entry in report["files"]:
            entry["before"] = report["watched_files"][entry["path"]]
            entry["after"].update(uid=os.getuid(), gid=os.getgid())
            after = entry["after"]
            target = (tx.regular(after["content"].encode(), after["mode"], after["uid"], after["gid"])
                      if after["kind"] == "regular" else {**after, "mode": 0o777})
            entry["changed"] = not tx.same_file(entry["before"], target)
        return base.prepare_review(self.profile, report, network=self.ip, hostname=self.hostname,
                                   packages=self.packages, inspector=self.inspector)

    def launch(self):
        report = self.report()
        self.originals = {p: self.manager.fs.snapshot(p) for p in report["watched_files"]}
        run_id = base.launch_reviewed(self.manager, self.supervisor, report, refresh=self.report,
                                     confirm=lambda question: "y", output=lambda value: None)
        self.run_id = run_id
        return run_id

    def apply(self):
        self.launch()
        self.supervisor.apply_fixture(self.run_id)

    def restored(self):
        for path, before in self.originals.items():
            self.assertTrue(tx.same_file(self.manager.fs.snapshot(path), before), path)
        self.assertEqual(self.ip.snapshot(), self.before)
        self.assertEqual(self.hostname.value, "oldhost")

    def package_journal(self):
        return self.supervisor.packages(self.run_id, self.supervisor.load(self.run_id))

    def test_decline_confirms_once_and_creates_no_state_or_target_changes(self):
        report = self.report()
        before = {p: tx.fingerprint(self.manager.fs.snapshot(p)) for p in report["watched_files"]}
        prompts = []
        result = base.launch_reviewed(self.manager, self.supervisor, report, refresh=self.report,
                    confirm=lambda question: prompts.append(question) or "", output=lambda value: None)
        self.assertIsNone(result)
        self.assertEqual(prompts, ["Apply? [y/N] "])
        self.assertFalse(self.manager.state_dir.exists())
        self.assertEqual(before, {p: tx.fingerprint(self.manager.fs.snapshot(p)) for p in before})
        self.assertEqual(self.ip.calls + self.hostname.calls + self.packages.calls, [])

    def test_full_base_finishes_packages_before_ready_and_defers_old_address_removal(self):
        self.apply()
        self.assertEqual(self.hostname.value, self.profile.hostname)
        self.assertEqual(self.packages.calls, [("update", []), ("install", ["ccze"])])
        self.assertIn(self.ip.old_address, self.ip.objects)
        self.assertEqual((self.root / "etc/hostname").read_text(), self.profile.hostname + "\n")
        self.assertEqual((self.root / "etc/default/locale").read_text(), 'LANG="C.UTF-8"\n')
        self.assertIn("Europe/Moscow", (self.root / "home/razis/.profile").read_text())
        self.assertEqual(os.readlink(self.root / "etc/localtime"), "/usr/share/zoneinfo/UTC")
        self.assertEqual(self.package_journal().load()["phase"], "completed")
        self.supervisor.acknowledge(self.run_id)
        self.assertNotIn(self.ip.old_address, self.ip.objects)
        healthy = self.ip.snapshot()
        self.supervisor.recover(self.run_id)
        self.assertEqual(self.ip.snapshot(), healthy)
        self.assertEqual(self.package_journal().load()["phase"], "completed")

    def test_update_failure_rolls_back_settings_without_running_install(self):
        self.packages.failed = "update"
        with self.assertRaises(tx.RecoveryError):
            self.apply()
        self.assertIsNone(self.supervisor.load(self.run_id)["acknowledgment"]["ready_ticks"])
        self.supervisor.recover(self.run_id)
        self.restored()
        self.assertEqual(self.packages.calls, [("update", [])])
        self.assertEqual(self.package_journal().load()["phase"], "retained")

    def test_failed_partial_install_keeps_installed_packages_after_rollback(self):
        self.packages.failed, self.packages.partial = "install", True
        with self.assertRaises(tx.RecoveryError):
            self.apply()
        self.supervisor.recover(self.run_id)
        self.restored()
        self.assertIn("ccze", self.packages.names)
        self.assertEqual([op for op, names in self.packages.calls], ["update", "install"])
        self.assertFalse(self.package_journal().load()["manual_attention"])

    def test_writer_death_after_package_intent_is_diagnosed_without_repair(self):
        self.launch()
        def die(operation, names):
            if operation == "install":
                self.assertEqual(self.package_journal().load()["steps"][operation], "intent")
                self.packages.names.update(names)
                raise KeyboardInterrupt()
        self.packages.on_run = die
        with self.assertRaises(KeyboardInterrupt):
            self.supervisor.apply_fixture(self.run_id)
        self.packages.on_run = lambda *args: None
        self.supervisor.recover(self.run_id)
        self.restored()
        self.assertIn("ccze", self.packages.names)
        self.assertEqual(len(self.packages.calls), 2)

    def test_broken_package_state_blocks_ack_but_does_not_block_network_recovery(self):
        self.apply()
        self.packages.audit = "An unpacked package requires manual attention\n"
        with self.assertRaises(tx.TransactionError):
            self.supervisor.acknowledge(self.run_id)
        self.assertIn(self.ip.old_address, self.ip.objects)
        self.supervisor.recover(self.run_id)
        self.restored()
        self.assertTrue(self.package_journal().load()["manual_attention"])
        self.assertIsNone(self.manager._active())

    def test_external_hostname_edit_is_preserved_while_files_and_network_restore(self):
        self.apply()
        self.hostname.value = "external-host"
        with self.assertRaises(tx.RecoveryError):
            self.supervisor.recover(self.run_id)
        self.assertEqual(self.hostname.value, "external-host")
        self.assertEqual(self.ip.snapshot(), self.before)
        self.assertEqual((self.root / "etc/hostname").read_text(), "oldhost\n")
        self.assertEqual(self.manager._active(), self.run_id)

    def test_old_transport_cannot_trigger_deferred_address_deletion(self):
        self.apply()
        self.inspector.started = 50
        with self.assertRaises(tx.TransactionError):
            self.supervisor.acknowledge(self.run_id)
        self.assertIn(self.ip.old_address, self.ip.objects)
        self.supervisor.recover(self.run_id)
        self.restored()

    def test_transport_change_after_deferred_deletion_still_rolls_back(self):
        self.apply()
        capture = self.inspector.capture
        def changed(account, **options):
            value = capture(account, **options)
            if self.ip.old_address not in self.ip.objects and value is not None:
                value["socket_inode"] += 1
            return value
        with mock.patch.object(self.inspector, "capture", side_effect=changed), self.assertRaises(tx.TransactionError):
            self.supervisor.acknowledge(self.run_id)
        self.assertNotIn(self.ip.old_address, self.ip.objects)
        self.supervisor.recover(self.run_id)
        self.restored()
        self.assertIn("ccze", self.packages.names)

    def test_replacement_hostname_namespace_is_preserved(self):
        self.apply()
        self.hostname.namespace["inode"] += 1
        with self.assertRaises(tx.RecoveryError):
            self.supervisor.recover(self.run_id)
        self.assertEqual(self.hostname.calls, [self.profile.hostname])
        self.assertEqual(self.ip.snapshot(), self.before)
        self.assertEqual((self.root / "etc/hostname").read_text(), "oldhost\n")

    def test_package_change_after_review_stops_before_file_writes(self):
        report = self.report()
        self.packages.names.add("ccze")
        with self.assertRaises(tx.StalePlan):
            base.launch_reviewed(self.manager, self.supervisor, report, refresh=self.report,
                                 confirm=lambda question: "y", output=lambda value: None)
        self.assertFalse(self.manager.state_dir.exists())
        self.assertEqual((self.root / "etc/hostname").read_text(), "oldhost\n")

    def test_healthy_second_run_has_no_file_backups_rewrites_or_install(self):
        self.apply()
        self.supervisor.acknowledge(self.run_id)
        healthy_report = self.report()
        self.assertFalse(any(entry["changed"] for entry in healthy_report["files"]))
        fingerprints = {p: tx.fingerprint(self.manager.fs.snapshot(p)) for p in healthy_report["watched_files"]}
        self.inspector.now, self.inspector.started = 300, 400
        self.run_id = base.launch_reviewed(self.manager, self.supervisor, healthy_report, refresh=self.report,
                                          confirm=lambda question: "y", output=lambda value: None)
        self.supervisor.apply_fixture(self.run_id)
        self.supervisor.acknowledge(self.run_id)
        self.assertEqual(self.manager._run(self.run_id)[0]["files"], [])
        self.assertEqual(fingerprints, {p: tx.fingerprint(self.manager.fs.snapshot(p)) for p in fingerprints})
        self.assertEqual(self.packages.calls, [("update", []), ("install", ["ccze"]), ("update", [])])

    def test_expired_guard_after_apt_keeps_ready_marker_unset(self):
        self.launch()
        self.packages.on_run = lambda operation, names: self.systemd.active_units.clear() if operation == "install" else None
        with self.assertRaises(tx.RecoveryError):
            self.supervisor.apply_fixture(self.run_id)
        self.assertIsNone(self.supervisor.load(self.run_id)["acknowledgment"]["ready_ticks"])
        self.supervisor.recover(self.run_id)
        self.restored()

    def test_production_target_remains_gated_before_a_confirmation(self):
        manager = mock.Mock()
        manager.fs.root = Path("/")
        confirm = mock.Mock(return_value="y")
        with self.assertRaisesRegex(tx.TransactionError, "gated"):
            base.launch_reviewed(manager, self.supervisor, {}, refresh=lambda: {}, confirm=confirm)
        confirm.assert_not_called()


class PackageTests(unittest.TestCase):
    def test_held_installed_packages_count_as_installed(self):
        value = pkg.inventory("ccze\t1.0\thi \n", "")
        self.assertTrue(value["healthy"])
        self.assertIn("ccze", pkg.installed(value))

    def test_unconfigured_packages_and_audit_output_are_unhealthy(self):
        self.assertFalse(pkg.inventory("ccze\t1.0\tiU \n", "")["healthy"])
        self.assertFalse(pkg.inventory("ccze\t1.0\tii \n", "Needs configuration\n")["healthy"])

    def test_invalid_or_duplicate_package_inventory_is_rejected(self):
        for output in ("ccze\t1.0\tii \nccze\t1.0\tii \n", "--remove\t1.0\tii \n", "ccze\t1.0\tii\n"):
            with self.assertRaises(tx.TransactionError):
                pkg.inventory(output, "")

    def test_only_fixed_selected_package_operations_can_run(self):
        backend = pkg.AptBackend(Path("/fixture"))
        with mock.patch.object(backend, "command", return_value={"returncode": 0}) as execute:
            backend.run("update", [])
            backend.run("install", ["ccze"])
            self.assertEqual(execute.call_args.args[0], [*bootstrap.APT_INSTALL, "ccze"])
            for operation, names in (("remove", ["ccze"]), ("install", ["bash"]), ("install", ["ccze", "ccze"]), ("update", ["ccze"])):
                with self.assertRaises(tx.TransactionError):
                    backend.run(operation, names)

    def test_system_package_mutation_is_gated(self):
        backend = pkg.AptBackend(Path("/"))
        with self.assertRaisesRegex(tx.TransactionError, "not enabled"):
            backend.run("update", [])

    def test_same_prefix_ipv4_move_is_rejected_before_mutation(self):
        profile = bootstrap.Profile.from_dict({**host_fixtures.EXAMPLE, "ipv4_cidr": "192.0.2.20/24",
                                              "ipv4_gateway": "192.0.2.1", "motd": False}, current_user="razis")
        before = net_fixtures.FakeIP().snapshot()
        before["objects"][next(i for i, obj in enumerate(before["objects"]) if obj["kind"] == "address")] = \
            guard.net.normalized_object({"kind": "address", "family": 4, "cidr": "192.0.2.10/24"}, "ens3")
        with self.assertRaisesRegex(tx.TransactionError, "secondary"):
            base.network_operations(profile, before)


if __name__ == "__main__":
    unittest.main()
