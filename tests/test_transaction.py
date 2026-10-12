"""File recovery and interruption tests. Every write stays in a temporary root."""

import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import transaction as tx


class TransactionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.root = self.directory / "host"
        self.state = self.directory / "state"
        for path in ("etc/network/interfaces.d", "home/invoker"):
            (self.root / path).mkdir(parents=True)
        self.file("/etc/hostname").write_bytes(b"old-host\n")
        self.file("/etc/hostname").chmod(0o640)
        os.utime(self.file("/etc/hostname"), ns=(1_700_000_000_000_000_000,) * 2)
        self.file("/etc/resolv.conf").write_bytes(b"nameserver 192.0.2.53\n")
        self.file("/etc/localtime").symlink_to("../old/zoneinfo")
        self.file("/etc/watched.conf").write_text("unrelated\n")
        self.manager = tx.FileTransaction(root=self.root, state_dir=self.state)
        self.plan = self.make_plan()
        self.originals = {path: self.manager.fs.snapshot(path) for path in self.plan["watched_files"]}

    def file(self, path):
        return self.root / path.lstrip("/")

    def make_plan(self):
        owner, group = os.geteuid(), os.getegid()
        values = {"/etc/hostname": tx.regular(b"new-host\n", 0o640, owner, group),
                  "/etc/resolv.conf": tx.regular(b"nameserver 1.1.1.1\n", 0o644, owner, group),
                  "/etc/localtime": {"kind": "symlink", "target": "/usr/share/zoneinfo/UTC",
                                     "mode": 0o777, "uid": owner, "gid": group, "sha256": None},
                  "/home/invoker/.profile": tx.regular(b"export TZ=Europe/Moscow\n", 0o644, owner, group)}
        watched = {path: tx.fingerprint(self.manager.fs.snapshot(path))
                   for path in (*values, "/etc/watched.conf")}
        files = []
        for path, value in values.items():
            after = copy.deepcopy(value)
            if value["kind"] == "regular":
                after["content"] = base64.b64decode(after.pop("data")).decode()
            files.append({"path": path, "before": watched[path], "after": after,
                          "changed": not tx.same_file(watched[path], value)})
        return {"file_plan_available": True, "blockers": [], "files": files,
                "watched_files": watched,
                "watched_patterns": {"/etc/network/interfaces.d/*": []},
                "facts": {"interface": {"ifname": "ens3"}, "routes-4": [{"dst": "default"}],
                          "account": {"uid": owner}, "services": {"networking.service": "active"}}}

    def prepare(self):
        return self.manager.prepare(self.plan, refresh=lambda: copy.deepcopy(self.plan))

    def apply(self, run_id):
        self.manager.apply_files(run_id, refresh=lambda: copy.deepcopy(self.plan))

    def assert_originals(self):
        for path, expected in self.originals.items():
            actual = self.manager.fs.snapshot(path)
            self.assertTrue(tx.same_file(actual, expected), path)
            if expected["kind"] != "absent":
                self.assertEqual(actual["mtime_ns"], expected["mtime_ns"], path)

    def child(self, code, *arguments):
        return subprocess.run([sys.executable, "-I", "-c", code, str(self.root), str(self.state),
                               *arguments], cwd=Path(__file__).resolve().parents[1],
                              capture_output=True, text=True, timeout=12,
                              env={"PATH": os.defpath, "PYTHONDONTWRITEBYTECODE": "1"})

    def test_prepare_saves_only_changed_originals_without_target_writes(self):
        run_id = self.prepare()
        self.assertRegex(run_id, r"^[0-9a-f]{32}$")
        self.assert_originals()
        backup = json.loads((self.state / "runs" / run_id / "backup.json").read_text())
        self.assertEqual(len(backup["files"]), 4)
        self.assertNotIn("/etc/watched.conf", [entry["path"] for entry in backup["files"]])
        self.assertEqual(self.manager.status(run_id)["phase"], "prepared")

    def test_apply_and_recover_types_contents_modes_owners_and_mtimes(self):
        run_id = self.prepare()
        backup = self.state / "runs" / run_id / "backup.json"
        saved_bytes = backup.read_bytes()
        self.apply(run_id)
        self.assertEqual(self.file("/etc/hostname").read_text(), "new-host\n")
        self.assertEqual(os.readlink(self.file("/etc/localtime")), "/usr/share/zoneinfo/UTC")
        self.assertTrue(self.file("/home/invoker/.profile").exists())
        self.assertEqual(self.manager.status(run_id)["phase"], "applied")
        self.manager.recover(run_id)
        self.assert_originals()
        self.assertEqual(backup.read_bytes(), saved_bytes)
        self.assertFalse((self.state / "active.json").exists())

    def test_regular_localtime_restores_as_regular_after_symlink_candidate(self):
        self.file("/etc/localtime").unlink()
        self.file("/etc/localtime").write_bytes(b"\x00old-zoneinfo\xff")
        self.file("/etc/localtime").chmod(0o600)
        self.plan = self.make_plan()
        self.originals = {path: self.manager.fs.snapshot(path) for path in self.plan["watched_files"]}
        run_id = self.prepare()
        self.apply(run_id)
        self.manager.recover(run_id)
        self.assert_originals()

    @unittest.skipUnless(os.geteuid() == 0, "Different UID/GID restoration requires root")
    def test_nonroot_user_file_ownership_is_preserved(self):
        for number, mapping in ((12345, "/proc/self/uid_map"), (12346, "/proc/self/gid_map")):
            ranges = [tuple(map(int, line.split())) for line in Path(mapping).read_text().splitlines()]
            if not any(start <= number < start + count for start, _, count in ranges):
                self.skipTest("Test UID/GID is not mapped in this container; runs in Debian CI")
        path = "/home/invoker/.profile"
        self.file(path).write_bytes(b"user content\n")
        os.chown(self.file(path), 12345, 12346)
        self.plan = self.make_plan()
        entry = next(entry for entry in self.plan["files"] if entry["path"] == path)
        entry["after"].update(uid=12345, gid=12346)
        run_id = self.prepare()
        self.apply(run_id)
        self.assertEqual((self.file(path).stat().st_uid, self.file(path).stat().st_gid), (12345, 12346))
        self.manager.recover(run_id)
        self.assertEqual(self.file(path).read_bytes(), b"user content\n")
        self.assertEqual((self.file(path).stat().st_uid, self.file(path).stat().st_gid), (12345, 12346))

    def test_recovery_is_idempotent_without_target_rewrites(self):
        run_id = self.prepare()
        self.apply(run_id)
        self.manager.recover(run_id)
        restored = {path: tx.fingerprint(self.manager.fs.snapshot(path)) for path in self.originals}
        self.manager.recover(run_id)
        self.assertEqual(restored, {path: tx.fingerprint(self.manager.fs.snapshot(path)) for path in self.originals})

    def test_healthy_second_plan_does_not_create_state_or_backups(self):
        run_id = self.prepare()
        self.apply(run_id)
        self.manager.commit(run_id)
        healthy = self.make_plan()
        fingerprints = copy.deepcopy(healthy["watched_files"])
        empty_state = self.directory / "unused-state"
        manager = tx.FileTransaction(root=self.root, state_dir=empty_state)
        self.assertIsNone(manager.prepare(healthy, refresh=lambda: healthy))
        self.assertFalse(empty_state.exists())
        self.assertEqual(fingerprints, self.make_plan()["watched_files"])

    def test_stale_file_is_rejected_even_if_refresh_returns_old_object(self):
        self.file("/etc/hostname").write_text("external\n")
        with self.assertRaises(tx.StalePlan):
            self.prepare()
        self.assertFalse(self.state.exists())
        self.assertEqual(self.file("/etc/hostname").read_text(), "external\n")

    def test_metadata_only_change_is_stale(self):
        self.file("/etc/hostname").chmod(0o600)
        with self.assertRaises(tx.StalePlan):
            self.prepare()
        self.assertFalse(self.state.exists())

    def test_new_include_fragment_is_stale_even_with_old_refresh_result(self):
        self.file("/etc/network/interfaces.d/new").write_text("# new fragment\n")
        with self.assertRaisesRegex(tx.StalePlan, "inventory changed"):
            self.prepare()
        self.assertFalse(self.state.exists())

    def test_live_routes_services_and_account_changes_reject_reviewed_plan(self):
        for key in ("routes-4", "services", "account"):
            with self.subTest(key=key):
                changed = copy.deepcopy(self.plan)
                changed["facts"][key] = {}
                with self.assertRaises(tx.StalePlan):
                    self.manager.prepare(self.plan, refresh=lambda: changed)
                self.assertFalse(self.state.exists())

    def test_change_while_acquiring_lock_is_rejected_before_backup(self):
        changed = copy.deepcopy(self.plan)
        changed["facts"]["interface"]["ifname"] = "other"
        with self.assertRaises(tx.StalePlan):
            self.manager.prepare(self.plan, refresh=mock.Mock(side_effect=[self.plan, changed]))
        self.assertFalse((self.state / "runs").exists())
        self.assert_originals()

    def test_change_after_backup_in_unwritten_file_blocks_first_write(self):
        run_id = self.prepare()
        self.file("/etc/watched.conf").write_text("external\n")
        with self.assertRaises(tx.StalePlan):
            self.apply(run_id)
        self.assertEqual(self.file("/etc/hostname").read_bytes(), b"old-host\n")
        self.assertEqual(self.manager.status(run_id)["attempted"], [])
        self.manager.recover(run_id)
        self.assertEqual(self.file("/etc/watched.conf").read_text(), "external\n")

    def test_pending_run_prevents_a_second_run(self):
        run_id = self.prepare()
        with self.assertRaises(tx.BusyRun):
            self.prepare()
        self.manager.recover(run_id)
        self.assertNotEqual(self.prepare(), run_id)

    def test_noop_plan_cannot_skip_pending_recovery(self):
        run_id = self.prepare()
        self.apply(run_id)
        healthy = self.make_plan()
        with self.assertRaises(tx.BusyRun):
            self.manager.prepare(healthy, refresh=lambda: healthy)

    def test_lock_excludes_a_separate_recovery_process(self):
        run_id = self.prepare()
        code = """
import sys
from pathlib import Path
sys.path.insert(0, str(Path.cwd()))
import transaction as tx
try:
    tx.FileTransaction(root=Path(sys.argv[1]), state_dir=Path(sys.argv[2])).recover(sys.argv[3])
except tx.BusyRun:
    raise SystemExit(17)
"""
        with self.manager._lock():
            result = self.child(code, run_id)
        self.assertEqual(result.returncode, 17, result.stderr)
        self.assert_originals()

    def test_write_failure_rolls_back_prior_writes(self):
        run_id = self.prepare()
        replace = self.manager.fs.replace
        calls = 0
        def fail(path, value, **options):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("injected write failure")
            return replace(path, value, **options)
        with mock.patch.object(self.manager.fs, "replace", side_effect=fail), self.assertRaises(OSError):
            self.apply(run_id)
        self.assert_originals()
        self.assertEqual(self.manager.status(run_id)["phase"], "rolled_back")

    def test_keyboard_interrupt_rolls_back(self):
        run_id = self.prepare()
        replace = self.manager.fs.replace
        def interrupt(path, value, **options):
            if path == "/etc/localtime" and value["target"] == "/usr/share/zoneinfo/UTC":
                raise KeyboardInterrupt()
            return replace(path, value, **options)
        with mock.patch.object(self.manager.fs, "replace", side_effect=interrupt), self.assertRaises(KeyboardInterrupt):
            self.apply(run_id)
        self.assert_originals()

    def test_replace_failure_leaves_no_temporary_files(self):
        run_id = self.prepare()
        replace = tx.os.replace
        def fail(source, destination, **options):
            if destination == "hostname":
                raise OSError("injected atomic replacement failure")
            return replace(source, destination, **options)
        with mock.patch.object(tx.os, "replace", side_effect=fail), self.assertRaises(OSError):
            self.apply(run_id)
        self.assert_originals()
        self.assertEqual(list(self.root.rglob(".rzandal-*")), [])

    def test_fsync_failure_after_replace_can_still_restore_original(self):
        run_id = self.prepare()
        fsync = tx.os.fsync
        parent_inode = self.file("/etc").stat().st_ino
        injected = False
        def fail_once(descriptor):
            nonlocal injected
            if (not injected and os.fstat(descriptor).st_ino == parent_inode
                    and self.file("/etc/hostname").read_bytes() == b"new-host\n"):
                injected = True
                raise OSError("injected directory fsync failure")
            return fsync(descriptor)
        with mock.patch.object(tx.os, "fsync", side_effect=fail_once), self.assertRaises(OSError):
            self.apply(run_id)
        self.assertTrue(injected)
        self.assert_originals()

    def test_sigkill_before_and_after_replace_is_recoverable_by_another_process(self):
        writer = """
import json, os, signal, sys
from pathlib import Path
sys.path.insert(0, str(Path.cwd()))
import transaction as tx
manager = tx.FileTransaction(root=Path(sys.argv[1]), state_dir=Path(sys.argv[2]))
plan = json.loads(Path(sys.argv[4]).read_text())
replace = manager.fs.replace
def interrupted(path, value, **options):
    if sys.argv[5] == 'after':
        replace(path, value, **options)
    os.kill(os.getpid(), signal.SIGKILL)
manager.fs.replace = interrupted
manager.apply_files(sys.argv[3], refresh=lambda: plan)
"""
        recovery = """
import sys
from pathlib import Path
sys.path.insert(0, str(Path.cwd()))
import transaction as tx
manager = tx.FileTransaction(root=Path(sys.argv[1]), state_dir=Path(sys.argv[2]))
assert manager.recover(sys.argv[3])['phase'] == 'rolled_back'
"""
        for point in ("before", "after"):
            with self.subTest(point=point):
                self.plan = self.make_plan()
                run_id = self.prepare()
                plan_file = self.directory / "plan.json"
                plan_file.write_text(json.dumps(self.plan))
                killed = self.child(writer, run_id, str(plan_file), point)
                self.assertEqual(killed.returncode, -signal.SIGKILL, killed.stderr)
                self.assertEqual(self.manager.status(run_id)["phase"], "applying")
                recovered = self.child(recovery, run_id)
                self.assertEqual(recovered.returncode, 0, recovered.stderr)
                self.assert_originals()

    def test_external_edit_is_preserved_and_other_files_are_restored(self):
        run_id = self.prepare()
        self.apply(run_id)
        self.file("/etc/hostname").write_bytes(b"external admin edit\n")
        with self.assertRaisesRegex(tx.RecoveryError, "external change"):
            self.manager.recover(run_id)
        self.assertEqual(self.file("/etc/hostname").read_bytes(), b"external admin edit\n")
        for path in self.originals.keys() - {"/etc/hostname"}:
            self.assertTrue(tx.same_file(self.manager.fs.snapshot(path), self.originals[path]), path)
        self.assertEqual(self.manager.status(run_id)["phase"], "recovery_failed")
        self.assertTrue((self.state / "active.json").exists())
        self.plan = self.make_plan()
        with self.assertRaises(tx.BusyRun):
            self.prepare()

    def test_failed_recovery_can_resume_after_manual_conflict_resolution(self):
        run_id = self.prepare()
        self.apply(run_id)
        self.file("/etc/hostname").write_bytes(b"external\n")
        with self.assertRaises(tx.RecoveryError):
            self.manager.recover(run_id)
        self.file("/etc/hostname").write_bytes(b"new-host\n")
        self.manager.recover(run_id)
        self.assert_originals()

    def test_commit_keeps_healthy_files_and_late_recovery_cannot_undo_it(self):
        run_id = self.prepare()
        self.apply(run_id)
        self.manager.commit(run_id)
        healthy = self.make_plan()["watched_files"]
        self.assertEqual(self.manager.recover(run_id)["phase"], "committed")
        self.assertEqual(self.make_plan()["watched_files"], healthy)

    def test_commit_rejects_modified_candidate(self):
        run_id = self.prepare()
        self.apply(run_id)
        self.file("/etc/resolv.conf").write_text("external\n")
        with self.assertRaises(tx.StalePlan):
            self.manager.commit(run_id)
        self.assertEqual(self.manager.status(run_id)["phase"], "applied")

    def test_old_final_run_cannot_clear_new_active_run(self):
        old = self.prepare()
        self.manager.recover(old)
        new = self.prepare()
        self.manager.recover(old)
        self.assertEqual(json.loads((self.state / "active.json").read_text())["run_id"], new)

    def test_terminal_journal_survives_failure_to_clear_pointer(self):
        run_id = self.prepare()
        self.apply(run_id)
        with mock.patch.object(self.manager, "_clear", side_effect=OSError("pointer failure")), self.assertRaises(OSError):
            self.manager.commit(run_id)
        self.assertEqual(self.manager.status(run_id)["phase"], "committed")
        healthy = self.make_plan()
        # Explicit recovery finalizes housekeeping without touching healthy files.
        self.manager.recover(run_id)
        self.assertEqual(self.make_plan(), healthy)

    def test_private_state_permissions_even_with_permissive_umask(self):
        previous = os.umask(0)
        try:
            self.prepare()
        finally:
            os.umask(previous)
        for path in (self.state, *self.state.rglob("*")):
            self.assertEqual(path.stat().st_mode & 0o777, 0o700 if path.is_dir() else 0o600, path)
            self.assertEqual(path.stat().st_uid, os.geteuid(), path)

    def test_public_state_directory_is_rejected_without_chmod_or_target_changes(self):
        self.state.mkdir(mode=0o755)
        with self.assertRaises(tx.TransactionError):
            self.prepare()
        self.assertEqual(self.state.stat().st_mode & 0o777, 0o755)
        self.assert_originals()

    def test_symlink_state_and_symlink_state_parent_are_rejected(self):
        outside = self.directory / "outside"
        outside.mkdir(mode=0o700)
        self.state.symlink_to(outside, target_is_directory=True)
        with self.assertRaises(OSError):
            self.prepare()
        self.assertEqual(list(outside.iterdir()), [])
        manager = tx.FileTransaction(root=self.root, state_dir=self.state / "nested")
        with self.assertRaises(OSError):
            manager.prepare(self.plan, refresh=lambda: self.plan)
        self.assertEqual(list(outside.iterdir()), [])

    def test_parent_symlink_swap_cannot_write_to_other_directory(self):
        run_id = self.prepare()
        outside = self.directory / "outside"
        outside.mkdir()
        victim = outside / ".profile"
        victim.write_bytes(b"victim\n")
        self.file("/home/invoker").rmdir()
        self.file("/home/invoker").symlink_to(outside, target_is_directory=True)
        with self.assertRaises(OSError):
            self.apply(run_id)
        self.assertEqual(victim.read_bytes(), b"victim\n")
        self.assertEqual(self.file("/etc/hostname").read_bytes(), b"old-host\n")

    def test_final_symlink_swap_cannot_write_through_to_victim(self):
        run_id = self.prepare()
        victim = self.directory / "victim"
        victim.write_bytes(b"victim\n")
        self.file("/etc/hostname").unlink()
        self.file("/etc/hostname").symlink_to(victim)
        with self.assertRaises(tx.StalePlan):
            self.apply(run_id)
        self.assertEqual(victim.read_bytes(), b"victim\n")

    def test_hardlinks_are_rejected(self):
        os.link(self.file("/etc/hostname"), self.directory / "alias")
        with self.assertRaises(tx.TransactionError):
            self.prepare()
        self.assertFalse(self.state.exists())

    def test_corrupt_backup_and_journal_stop_before_any_restore(self):
        run_id = self.prepare()
        self.apply(run_id)
        backup_file = self.state / "runs" / run_id / "backup.json"
        original = backup_file.read_bytes()
        backup = json.loads(original)
        backup["files"][0]["before"]["data"] = base64.b64encode(b"wrong original").decode()
        backup_file.write_text(json.dumps(backup))
        with self.assertRaises(tx.TransactionError):
            self.manager.recover(run_id)
        self.assertEqual(self.file("/etc/hostname").read_bytes(), b"new-host\n")
        backup_file.write_bytes(original)
        journal_file = self.state / "runs" / run_id / "journal.json"
        journal_file.write_text('{"run_id":"x","run_id":"y"}')
        with self.assertRaises(tx.TransactionError):
            self.manager.recover(run_id)
        self.assertEqual(self.file("/etc/hostname").read_bytes(), b"new-host\n")

    def test_checksum_detects_manifest_edit_even_with_valid_blob_hash(self):
        run_id = self.prepare()
        self.apply(run_id)
        path = self.state / "runs" / run_id / "backup.json"
        backup = json.loads(path.read_text())
        backup["files"][0]["before"].update(tx.regular(b"different\n", 0o640, os.geteuid(), os.getegid()))
        del backup["_sha256"]
        self.manager._save(f"/runs/{run_id}/backup.json", backup)
        with self.assertRaisesRegex(tx.TransactionError, "backup checksum"):
            self.manager.recover(run_id)
        self.assertEqual(self.file("/etc/hostname").read_bytes(), b"new-host\n")

    def test_run_id_traversal_and_corrupt_phase_are_rejected(self):
        run_id = self.prepare()
        for invalid in ("../backup", "a" * 31, "A" * 32, "a" * 32 + "/../other"):
            with self.subTest(invalid=invalid), self.assertRaises(tx.TransactionError):
                self.manager.recover(invalid)
        path = self.state / "runs" / run_id / "journal.json"
        journal = json.loads(path.read_text())
        journal["phase"] = []
        del journal["_sha256"]
        self.manager._save(f"/runs/{run_id}/journal.json", journal)
        with self.assertRaises(tx.TransactionError):
            self.manager.recover(run_id)
        self.assert_originals()

    def test_valid_checksum_cannot_hide_inconsistent_phase_and_write_intent(self):
        run_id = self.prepare()
        self.apply(run_id)
        journal = self.manager.status(run_id)
        journal["attempted"] = []
        self.manager._save(f"/runs/{run_id}/journal.json", journal)
        with self.assertRaisesRegex(tx.TransactionError, "inconsistent"):
            self.manager.recover(run_id)
        self.assertEqual(self.file("/etc/hostname").read_bytes(), b"new-host\n")

    def test_extended_attributes_are_blocked_before_backup(self):
        try:
            os.setxattr(self.file("/etc/hostname"), "user.rzandal-fixture", b"preserve me")
        except OSError as error:
            self.skipTest(f"Fixture filesystem does not support user xattrs: {error}")
        with self.assertRaisesRegex(tx.TransactionError, "extended attributes"):
            self.prepare()
        self.assertFalse(self.state.exists())
        self.assertEqual(os.getxattr(self.file("/etc/hostname"), "user.rzandal-fixture"), b"preserve me")

    def test_blocked_plan_and_inconsistent_candidates_do_not_create_state(self):
        for changed in ("blockers", "checksum", "flag", "duplicate"):
            plan = copy.deepcopy(self.plan)
            if changed == "blockers":
                plan["blockers"] = ["unsupported host"]
            elif changed == "checksum":
                plan["files"][0]["after"]["sha256"] = "0" * 64
            elif changed == "flag":
                plan["files"][0]["changed"] = False
            else:
                plan["files"].append(plan["files"][0])
            with self.subTest(changed=changed), self.assertRaises(tx.TransactionError):
                self.manager.prepare(plan, refresh=lambda: plan)
            self.assertFalse(self.state.exists())

    def test_large_combined_backup_can_exceed_one_file_limit(self):
        self.file("/etc/hostname").write_bytes(b"a" * (700 * 1024))
        self.file("/etc/resolv.conf").write_bytes(b"b" * (700 * 1024))
        self.plan = self.make_plan()
        run_id = self.prepare()
        self.assertGreater((self.state / "runs" / run_id / "backup.json").stat().st_size, tx.MAX_FILE_BYTES)
        self.apply(run_id)
        self.manager.recover(run_id)
        self.assertEqual(len(self.file("/etc/hostname").read_bytes()), 700 * 1024)

    def test_recovery_cli_exposes_no_apply_or_fixture_root_option(self):
        for arguments in (("apply", "0" * 32), ("status", "0" * 32, "--root", str(self.root))):
            result = subprocess.run([sys.executable, "transaction.py", *arguments],
                                    capture_output=True, text=True, cwd=Path(__file__).resolve().parents[1])
            self.assertEqual(result.returncode, 2)


@unittest.skipUnless(os.geteuid() == 0, "System UID metadata in the fixture requires root")
class PlannerTransactionIntegrationTests(unittest.TestCase):
    def test_actual_host_plan_applies_then_replans_without_changes(self):
        import bootstrap as app
        import preflight as host
        from types import SimpleNamespace
        from test_preflight import FixtureView, HostPlanTests, ACCOUNT

        fixture = HostPlanTests("test_full_plan_preserves_target_bytes_and_reports_exact_candidates")
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        account = SimpleNamespace(**vars(ACCOUNT))
        account.pw_uid, account.pw_gid = os.geteuid(), os.getegid()

        class ActualOwnershipView(FixtureView):
            def file(self, path):
                return host.SystemView.file(self, path)

        def refresh():
            with mock.patch.dict(os.environ, {"SSH_CONNECTION": "203.0.113.20 50000 192.0.2.10 22"}):
                return host.prepare_host_plan(fixture.profile, account, app.build_plan(fixture.profile),
                                              app.merge_profile_timezone, view=ActualOwnershipView(fixture.root))

        manager = tx.FileTransaction(root=fixture.root, state_dir=Path(temporary.name) / "state")
        plan = refresh()
        self.assertEqual(plan["blockers"], [])
        before = fixture.snapshot()
        run_id = manager.prepare(plan, refresh=refresh)
        self.assertEqual(fixture.snapshot(), before)
        manager.apply_files(run_id, refresh=refresh)
        healthy = refresh()
        self.assertEqual(healthy["blockers"], [])
        self.assertTrue(all(not entry["changed"] for entry in healthy["files"]))
        manager.commit(run_id)
        after = fixture.snapshot()
        self.assertIsNone(manager.prepare(healthy, refresh=refresh))
        self.assertEqual(fixture.snapshot(), after)


if __name__ == "__main__":
    unittest.main()
