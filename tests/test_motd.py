"""MOTD ordering, native-result boundaries and immutable staging regressions."""

import copy
from dataclasses import replace
import hashlib
import io
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

import recovery as guard
import transaction as tx
import test_base_apply as base_fixtures

motd, bootstrap = guard.motd, guard.bootstrap


def make_source(directory, *, payload=b"#!/bin/bash\nexit 0\n", version="0.4.0", installer=b"#!/bin/bash\nexit 0\n"):
    directory.mkdir(mode=0o700)
    data = {"install.sh": installer, "VERSION": (version + "\n").encode(), motd.PAYLOAD: payload,
            motd.COMMAND: b"#!/bin/bash\nexit 0\n"}
    data["SHA256SUMS"] = "".join(hashlib.sha256(data[p]).hexdigest() + "  " + p + "\n"
                                  for p in ("VERSION", motd.PAYLOAD, motd.COMMAND)).encode()
    release = copy.deepcopy(bootstrap.MOTD_RELEASE)
    release.update(version=version, source_ref="v" + version)
    release["files"] = {p: hashlib.sha256(data[p]).hexdigest() for p in motd.FILES}
    for path, content in data.items():
        file = directory / path
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_bytes(content)
        file.chmod(0o600)
    return motd.ReleaseSource(directory, release=release)


def healthy(release, *, code=0):
    return {"code": code, "data": {"schema_version": 1, "installed": True, "healthy": code in {0, 5},
            "desired_source_matches": code != 5, "source_ref": release["source_ref"], "version": release["version"],
            "payload_sha256": release["files"][motd.PAYLOAD], "command_sha256": release["files"][motd.COMMAND],
            "target_status": "valid", "command_status": "valid", "last_login_managed": False, "last_login_status": "unmanaged"}}


class FakeMOTD:
    def __init__(self, root):
        self.root = root
        self.health = {"code": 3, "data": {"schema_version": 1, "installed": False, "healthy": False, "desired_source_matches": False}}
        self.calls = []
        self.failure, self.partial = False, False
        self.on_run = lambda: None

    def check(self, source):
        source.inspect()
        return copy.deepcopy(self.health)

    def run(self, source, action, run_id):
        self.calls.append((action, run_id))
        self.on_run()
        if not self.failure or self.partial:
            for path in (motd.PAYLOAD, motd.COMMAND):
                file = self.root / path
                file.parent.mkdir(parents=True, exist_ok=True)
                file.write_bytes((source.directory / path).read_bytes())
                file.chmod(0o755)
            self.health = healthy(source.release, code=4 if self.failure else 0)
        return {"returncode": 9 if self.failure else 0, "output": "fixture", "errors": "", "truncated": False}


@unittest.skipUnless(os.geteuid() == 0, "Native protected-source/module contract requires root")
class ModuleTests(unittest.TestCase):
    def setUp(self):
        self.fixture = base_fixtures.BaseTests("test_full_base_finishes_packages_before_ready_and_defers_old_address_removal")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.root, self.manager, self.supervisor = self.fixture.root, self.fixture.manager, self.fixture.supervisor
        self.source = make_source(self.root / "motd-release")
        for path in ("etc/update-motd.d", "usr/local/bin", "var/lib", "etc/ssh/sshd_config.d"):
            (self.root / path).mkdir(parents=True, exist_ok=True)
        for path, data in (("etc/motd", b"Original MOTD\n"), ("etc/issue", b"Debian 13\n"),
                           ("etc/ssh/sshd_config.d/99-existing.conf", b"PrintLastLog no\n")):
            (self.root / path).write_bytes(data)
        self.backend = FakeMOTD(self.root)
        self.supervisor.motd_backend_factory = lambda root, **options: self.backend
        self.fixture.profile = replace(self.fixture.profile, motd=True)
        self.fixture.motd_review = {"motd_source": self.source, "motd_backend": self.backend}

    def apply(self):
        self.fixture.apply()
        self.run_id = self.fixture.run_id

    def committed(self):
        self.apply()
        self.supervisor.acknowledge(self.run_id)

    def module(self):
        return self.supervisor.motd_module(self.run_id, self.supervisor.load(self.run_id))

    def base_snapshot(self):
        return ({p: tx.fingerprint(self.manager.fs.snapshot(p)) for p in self.fixture.originals},
                self.fixture.ip.snapshot(), self.fixture.hostname.snapshot(), self.fixture.packages.inspect())

    def test_plan_checks_are_read_only_and_decline_creates_no_transaction(self):
        before = motd.inventory(self.root)
        report = self.fixture.report()
        self.assertEqual(report["motd_plan"]["action"], "install")
        output = []
        answer = guard.base.launch_reviewed(self.manager, self.supervisor, report, refresh=self.fixture.report,
                                            confirm=lambda question: "n", output=output.append)
        self.assertIsNone(answer)
        self.assertEqual(motd.inventory(self.root), before)
        self.assertFalse(self.manager.state_dir.exists())
        self.assertTrue(any("MOTD after Base commit: install" in text for text in output))
        self.assertEqual(self.backend.calls, [])

    def test_only_fresh_ssh_commit_queues_the_single_native_writer(self):
        self.apply()
        with self.assertRaises(tx.TransactionError):
            self.supervisor.apply_motd_fixture(self.run_id)
        self.fixture.inspector.started = 50
        with self.assertRaises(tx.TransactionError):
            self.supervisor.acknowledge(self.run_id)
        self.assertEqual(self.module().load()["phase"], "prepared")
        self.assertEqual(self.backend.calls, [])
        self.fixture.inspector.started = 200
        self.supervisor.acknowledge(self.run_id)
        self.assertEqual(self.manager.status(self.run_id)["phase"], "committed")
        self.assertEqual(self.module().load()["phase"], "queued")
        self.assertEqual(self.manager._module_active(), self.run_id)
        self.assertTrue((self.fixture.units / guard.unit_names(self.run_id)["boot"]).exists())
        self.supervisor.acknowledge(self.run_id)
        starts = [c for c in self.fixture.systemd.calls if c == ("start", "--no-block", guard.module_unit(self.run_id))]
        self.assertEqual(len(starts), 1)
        before = self.base_snapshot()
        self.supervisor.apply_motd_fixture(self.run_id)
        self.assertEqual(self.base_snapshot(), before)
        self.assertEqual(self.module().status()["phase"], "completed")
        self.assertIsNone(self.manager._module_active())
        self.assertEqual(list(self.fixture.units.iterdir()), [])
        self.assertEqual(self.supervisor.status(self.run_id)["motd"]["base_policy"], "preserved")
        self.supervisor.acknowledge(self.run_id)
        self.supervisor.apply_motd_fixture(self.run_id)
        self.assertEqual(len(self.backend.calls), 1)
        self.assertEqual((self.root / "etc/ssh/sshd_config.d/99-existing.conf").read_text(), "PrintLastLog no\n")

    def test_second_run_uses_native_health_without_install_or_file_rewrites(self):
        self.committed()
        self.supervisor.apply_motd_fixture(self.run_id)
        before = motd.inventory(self.root)
        self.assertEqual(self.fixture.report()["motd_plan"]["action"], "check")
        self.committed()
        self.supervisor.apply_motd_fixture(self.run_id)
        self.assertEqual(motd.inventory(self.root), before)
        self.assertEqual(len(self.backend.calls), 1)

    def test_module_failure_recovered_by_native_installer_preserves_committed_base(self):
        self.backend.failure = True
        self.committed()
        before = self.base_snapshot()
        self.supervisor.apply_motd_fixture(self.run_id)
        self.assertEqual(self.base_snapshot(), before)
        status = self.supervisor.status(self.run_id)
        self.assertEqual(status["phase"], "committed")
        self.assertEqual(status["motd"]["phase"], "failed")
        self.assertFalse(status["motd"]["manual_attention"])
        self.supervisor.recover(self.run_id)
        self.assertEqual(self.base_snapshot(), before)
        self.assertEqual(len(self.backend.calls), 1)

    def test_partial_native_failure_reports_attention_and_never_undoes_base(self):
        self.backend.failure, self.backend.partial = True, True
        self.committed()
        before = self.base_snapshot()
        self.supervisor.apply_motd_fixture(self.run_id)
        self.assertTrue(self.module().status()["manual_attention"])
        self.assertEqual(self.base_snapshot(), before)
        self.assertTrue((self.root / motd.PAYLOAD).exists())

    def test_unfinished_module_blocks_a_new_base_run(self):
        self.committed()
        report = self.fixture.report()
        with self.assertRaises(tx.BusyRun):
            self.manager.prepare(report, refresh=self.fixture.report, force_run=True)
        self.supervisor.recover(self.run_id)
        self.assertEqual(self.module().status()["phase"], "interrupted")
        self.assertIsNone(self.manager._module_active())

    def test_writer_death_leaves_intent_and_independent_observer_keeps_base(self):
        self.committed()
        before = self.base_snapshot()
        def die():
            self.assertEqual(self.module().load()["phase"], "running")
            raise KeyboardInterrupt()
        self.backend.on_run = die
        with self.assertRaises(KeyboardInterrupt):
            self.supervisor.apply_motd_fixture(self.run_id)
        self.supervisor.recover(self.run_id)
        self.assertEqual(self.module().status()["phase"], "interrupted")
        self.assertTrue(self.module().status()["manual_attention"])
        self.assertEqual(self.base_snapshot(), before)
        self.supervisor.acknowledge(self.run_id)
        self.assertEqual(len(self.backend.calls), 1)

    def test_boot_observation_of_interruption_preserves_committed_base(self):
        self.committed()
        before = self.base_snapshot()
        self.fixture.systemd.boot = "boot-two:12345"
        status = self.supervisor.recover(self.run_id, boot=True)
        self.assertEqual(status["phase"], "committed")
        self.assertEqual(status["motd"]["phase"], "interrupted")
        self.assertEqual(self.base_snapshot(), before)

    def test_apt_failure_cancels_motd_without_calling_native_installer(self):
        self.fixture.packages.failed = "update"
        with self.assertRaises(tx.RecoveryError):
            self.apply()
        self.run_id = self.fixture.run_id
        self.supervisor.recover(self.run_id)
        self.assertEqual(self.module().status()["phase"], "cancelled")
        self.assertEqual(self.backend.calls, [])
        self.fixture.restored()

    def test_source_tampering_stops_base_before_first_write(self):
        self.fixture.launch()
        self.run_id = self.fixture.run_id
        copied = self.module().source(self.module().load()["plan"])
        (copied.directory / "install.sh").write_text("#!/bin/bash\nexit 9\n")
        with self.assertRaises(tx.TransactionError):
            self.supervisor.apply_fixture(self.run_id)
        self.supervisor.recover(self.run_id)
        self.fixture.restored()
        self.assertEqual(self.backend.calls, [])

    def test_external_module_edit_before_ack_is_preserved_and_blocks_commit(self):
        self.apply()
        (self.root / "etc/motd").write_text("External edit\n")
        with self.assertRaises(tx.StalePlan):
            self.supervisor.acknowledge(self.run_id)
        self.supervisor.recover(self.run_id)
        self.assertEqual((self.root / "etc/motd").read_text(), "External edit\n")
        self.fixture.restored()
        self.assertEqual(self.backend.calls, [])

    def test_broken_base_after_commit_blocks_module_without_rollback(self):
        self.committed()
        (self.root / "etc/hostname").write_text("external-host\n")
        self.supervisor.apply_motd_fixture(self.run_id)
        self.assertEqual(self.module().status()["phase"], "failed")
        self.assertTrue(self.module().status()["manual_attention"])
        self.assertEqual(self.manager.status(self.run_id)["phase"], "committed")
        self.assertEqual((self.root / "etc/hostname").read_text(), "external-host\n")
        self.assertEqual(self.backend.calls, [])

    def test_healthy_same_ref_with_wrong_payload_is_not_a_noop(self):
        self.backend.health = healthy(self.source.release)
        self.backend.health["data"]["payload_sha256"] = "a" * 64
        with self.assertRaises(tx.TransactionError):
            self.fixture.report()

    def test_modified_state_requires_explicit_native_repair_in_review(self):
        self.backend.health = healthy(self.source.release, code=4)
        report = self.fixture.report()
        self.assertEqual(report["motd_plan"]["action"], "repair")
        self.committed()
        self.supervisor.apply_motd_fixture(self.run_id)
        self.assertEqual(self.backend.calls[0][0], "repair")

    def test_pin_checks_reject_even_a_self_consistent_modified_source(self):
        new = make_source(self.root / "different-release", payload=b"#!/bin/bash\nexit 9\n")
        with self.assertRaises(tx.TransactionError):
            motd.ReleaseSource(new.directory, release=self.source.release).inspect()


class HealthParserTests(unittest.TestCase):
    def test_native_health_codes_must_agree_with_json(self):
        for code in (0, 4, 5):
            value = healthy(bootstrap.MOTD_RELEASE, code=code)
            motd.validate_health(value)
            value["data"]["healthy"] = not value["data"]["healthy"]
            with self.assertRaises(tx.TransactionError):
                motd.validate_health(value)
        with self.assertRaises(tx.TransactionError):
            motd.validate_health({"code": 1, "data": {}})

    def test_production_mutation_is_gated_before_source_access(self):
        with self.assertRaises(tx.TransactionError):
            motd.NativeBackend(Path("/")).run(None, "install", "a" * 32)


@unittest.skipUnless(os.geteuid() == 0, "Protected download staging requires root")
class DownloadTests(unittest.TestCase):
    def test_downloads_use_one_commit_and_independent_pins(self):
        with tempfile.TemporaryDirectory(prefix="rzandal-motd-download-") as temporary:
            directory = Path(temporary)
            source = make_source(directory / "origin")
            urls = []
            def download(url, **options):
                urls.append(url)
                prefix = "https://raw.githubusercontent.com/" + source.release["repository"] + "/" + source.release["commit"] + "/"
                self.assertTrue(url.startswith(prefix))
                response = io.BytesIO((source.directory / url.removeprefix(prefix)).read_bytes())
                response.geturl = lambda: url
                return response
            with mock.patch.object(bootstrap, "MOTD_RELEASE", source.release), mock.patch.object(motd.urllib.request, "urlopen", download):
                staged = motd.stage_release(directory / "downloaded")
            self.assertEqual(staged.release, source.release)
            self.assertEqual(len(urls), len(motd.FILES))
            staged.inspect()

    def test_bad_installer_hash_is_refused_before_it_can_execute(self):
        with tempfile.TemporaryDirectory(prefix="rzandal-motd-download-") as temporary:
            directory = Path(temporary)
            source = make_source(directory / "origin")
            response = io.BytesIO(b"#!/bin/bash\nexit 9\n")
            response.geturl = lambda: "https://raw.githubusercontent.com/" + source.release["repository"] + "/" + source.release["commit"] + "/install.sh"
            with mock.patch.object(bootstrap, "MOTD_RELEASE", source.release), mock.patch.object(motd.urllib.request, "urlopen", return_value=response):
                with self.assertRaises(tx.TransactionError):
                    motd.stage_release(directory / "downloaded")
            self.assertFalse((directory / "downloaded/install.sh").exists())

