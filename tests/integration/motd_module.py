"""Native released MOTD through the committed Base lifecycle in disposable CI."""

import copy
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import shutil
import unittest

import base_application as fixture_base
import kernel_recovery as kernel

motd, bootstrap = kernel.guard.motd, kernel.guard.bootstrap
SOURCE = Path("/opt/rzandal-motd-release")


class MOTDFixture(fixture_base.BaseFixture):
    def __init__(self, *, payload=None, version=None, **options):
        super().__init__(**options)
        self.profile = replace(self.profile, motd=True)
        self.source_dir = self.directory / "motd-release"
        shutil.copytree(SOURCE, self.source_dir)
        release = copy.deepcopy(bootstrap.MOTD_RELEASE)
        if payload is not None:
            (self.source_dir / motd.PAYLOAD).write_bytes(payload)
        if version is not None:
            (self.source_dir / "VERSION").write_text(version + "\n")
            release.update(version=version, source_ref="v" + version)
        if payload is not None or version is not None:
            # Explicit trusted fixture pins; production downloads always use
            # bootstrap.MOTD_RELEASE. The released installer stays unmodified.
            data = {p: (self.source_dir / p).read_bytes() for p in motd.FILES if p != "SHA256SUMS"}
            manifest = "".join(hashlib.sha256(data[p]).hexdigest() + "  " + p + "\n"
                               for p in ("VERSION", motd.PAYLOAD, motd.COMMAND))
            (self.source_dir / "SHA256SUMS").write_text(manifest)
            release["files"] = {p: hashlib.sha256((self.source_dir / p).read_bytes()).hexdigest() for p in motd.FILES}
        self.motd_source = motd.ReleaseSource(self.source_dir, release=release)
        self.backend = motd.NativeBackend(self.root, namespace=self.kernel.namespace)
        self.motd_review = {"motd_source": self.motd_source, "motd_backend": self.backend}
        self.write("/etc/motd", "Original MOTD\n")
        self.write("/etc/issue", "Debian 13 fixture\n")
        self.write("/etc/update-motd.d/05-existing", "#!/bin/bash\nprintf 'Old MOTD\\n'\n")
        (self.root / "etc/update-motd.d/05-existing").chmod(0o751)
        self.write("/etc/ssh/sshd_config.d/99-existing.conf", "PrintLastLog no\n")
        self.proc = self.root / "proc"
        self.proc.mkdir(exist_ok=True)
        fixture_base.run(["mount", "-t", "proc", "-o", "ro,nosuid,nodev,noexec", "proc", str(self.proc)], check=True)
        mounted = self.proc.stat()
        self.proc_identity = (mounted.st_dev, mounted.st_ino)

    def module_status(self):
        return self.supervisor.status(self.run_id)["motd"]

    def completed(self):
        value = self.module_status()
        return value if value["phase"] in motd.TERMINAL else None

    def base_snapshot(self):
        return ({p: kernel.tx.fingerprint(self.manager.fs.snapshot(p)) for p in self.originals},
                self.kernel.ip.snapshot(), kernel.guard.base.HostnameBackend(self.root).snapshot(),
                kernel.guard.pkg.AptBackend(self.root).inspect())

    def close(self):
        try:
            if self.run_id is not None:
                kernel.wait_for(lambda: self.supervisor.recover(self.run_id), seconds=45)
        finally:
            try:
                info = self.proc.stat()
                if (info.st_dev, info.st_ino) != self.proc_identity:
                    raise RuntimeError("Owned fixture proc mount was replaced; preserving it")
                fixture_base.run(["umount", str(self.proc)], check=True)
            finally:
                super().close()


class NativeMOTDTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        kernel.require_container()
        motd.ReleaseSource(SOURCE).inspect()

    def fixture(self, **options):
        fixture = MOTDFixture(**options)
        self.addCleanup(fixture.close)
        return fixture

    def commit(self, fixture):
        result = fixture.peer.acknowledge()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(kernel.wait_for(lambda: fixture.manager._run(fixture.run_id)[1])["phase"], "committed")

    def test_released_install_and_second_run_preserve_base_and_ssh(self):
        fixture = self.fixture()
        before = motd.inventory(fixture.root)
        fixture.start()
        self.assertEqual(motd.inventory(fixture.root), before)
        self.assertEqual(fixture.module_status()["phase"], "prepared")
        self.commit(fixture)
        # A native writer owns the common lock. Wait for its terminal result
        # before querying state or beginning a second reviewed Base transition.
        status = kernel.wait_for(fixture.completed, seconds=45)
        self.assertEqual(status["phase"], "completed", json.dumps(status))
        self.assertFalse(status["manual_attention"])
        self.assertFalse(status["health"]["data"]["last_login_managed"])
        self.assertEqual((fixture.root / "etc/ssh/sshd_config.d/99-existing.conf").read_text(), "PrintLastLog no\n")
        manual = fixture.backend.command(["/usr/sbin/chroot", str(fixture.root), "/usr/local/bin/server-info"], timeout=10)
        self.assertEqual(manual["returncode"], 0, manual["errors"])
        self.assertIn("rzandal-ci-base running", manual["output"])
        health = fixture.backend.check(fixture.motd_source)
        self.assertTrue(motd.desired_health(health, bootstrap.MOTD_RELEASE))
        module_before = motd.inventory(fixture.root)
        base_before = fixture.base_snapshot()
        fixture.start()
        self.assertEqual(fixture.report["motd_plan"]["action"], "check")
        self.assertEqual(fixture.manager._run(fixture.run_id)[0]["files"], [])
        self.commit(fixture)
        status = kernel.wait_for(fixture.completed, seconds=30)
        self.assertEqual(status["phase"], "completed", json.dumps(status))
        self.assertIsNone(status["result"])
        self.assertEqual(motd.inventory(fixture.root), module_before)
        self.assertEqual(fixture.base_snapshot(), base_before)
        self.assertIsNone(fixture.manager._module_active())

    def test_native_failed_module_restores_motd_and_keeps_completed_base(self):
        fixture = self.fixture(payload=b"#!/bin/bash\nexit 9\n", version="0.4.1")
        module_before = motd.contents(motd.inventory(fixture.root))
        fixture.start()
        self.commit(fixture)
        status = kernel.wait_for(fixture.completed, seconds=45)
        base_before = fixture.base_snapshot()
        self.assertEqual(status["phase"], "failed", json.dumps(status))
        self.assertEqual(status["result"]["returncode"], 9)
        self.assertFalse(status["manual_attention"], json.dumps(status))
        self.assertEqual(motd.contents(motd.inventory(fixture.root)), module_before)
        self.assertEqual(fixture.manager.status(fixture.run_id)["phase"], "committed")
        fixture.supervisor.recover(fixture.run_id)
        self.assertEqual(fixture.base_snapshot(), base_before)

    def test_sigkill_reports_interruption_without_undoing_base_or_retrying(self):
        fixture = self.fixture(payload=b'#!/bin/bash\nprintf "%s\\n" "$$" > /run/rzandal-motd-sleeper.pid\nexec /bin/sleep 60\n', version="0.4.1")
        fixture.start()
        self.commit(fixture)
        marker = fixture.root / "run/rzandal-motd-sleeper.pid"
        kernel.wait_for(marker.is_file, seconds=20)
        child = int(marker.read_text().strip())
        started = kernel.guard.ssh.parse_stat(Path(f"/proc/{child}/stat").read_text())["start_ticks"]
        fixture.supervisor.systemd.command("kill", "--signal=SIGKILL", "--kill-whom=all", kernel.guard.module_unit(fixture.run_id))
        status = kernel.wait_for(fixture.completed, seconds=45)
        before = fixture.base_snapshot()
        self.assertEqual(status["phase"], "interrupted", json.dumps(status))
        self.assertTrue(status["manual_attention"])
        self.assertEqual(fixture.manager.status(fixture.run_id)["phase"], "committed")
        record = Path(f"/proc/{child}/stat")
        self.assertTrue(not record.exists() or kernel.guard.ssh.parse_stat(record.read_text())["start_ticks"] != started)
        result = fixture.peer.acknowledge()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(fixture.module_status()["phase"], "interrupted")
        self.assertEqual(fixture.base_snapshot(), before)
        self.assertFalse(fixture.supervisor.systemd.active(kernel.guard.module_unit(fixture.run_id)))

    def test_failed_base_never_starts_native_motd(self):
        fixture = self.fixture(broken_source=True)
        before = motd.inventory(fixture.root)
        fixture.launch()
        kernel.wait_for(fixture.rolled_back, seconds=35)
        self.assertEqual(fixture.module_status()["phase"], "cancelled")
        self.assertEqual(motd.inventory(fixture.root), before)
        self.assertIsNone(fixture.manager._module_active())
        fixture.assert_restored()


if __name__ == "__main__":
    unittest.main()
