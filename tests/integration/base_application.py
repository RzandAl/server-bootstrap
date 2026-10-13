"""Native Base/APT/hostname/SSH checks only in the owned disposable CI container."""

import copy
import json
import os
from pathlib import Path
import pwd
import select
import shutil
import socket
import stat
import subprocess
import sys
import unittest

import kernel_recovery as kernel
from ssh_acknowledgment import SSHPeer

base, pkg, bootstrap, host = kernel.guard.base, kernel.guard.pkg, kernel.guard.bootstrap, kernel.guard.host
TEMPLATE = Path("/opt/rzandal-base-template")
REPOSITORY = "deb [trusted=yes] file:/opt/rzandal-package-repo ./"


def run(arguments, **options):
    try:
        return subprocess.run(arguments, capture_output=True, text=True, timeout=15, **options)
    except subprocess.CalledProcessError as error:
        raise RuntimeError(f"Owned fixture command failed: {error.cmd!r}: {error.stderr.strip()}") from error


class UTSFixture:
    def __init__(self, directory):
        kernel.require_container()
        self.path = directory / "fixture-uts.ns"
        self.path.write_bytes(b"")
        self.path.chmod(0o600)
        code = "import socket, time; socket.sethostname(b'base-before-ci'); print('ready', flush=True); time.sleep(30)"
        process = subprocess.Popen(["unshare", "--uts", "/usr/bin/python3", "-I", "-c", code],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            if not select.select([process.stdout], [], [], 5)[0] or process.stdout.readline().strip() != "ready":
                raise RuntimeError("Owned UTS fixture did not become ready")
            run(["mount", "--bind", f"/proc/{process.pid}/ns/uts", str(self.path)], check=True)
            info = self.path.stat()
            self.identity = (info.st_dev, info.st_ino)
        finally:
            process.terminate()
            process.wait(timeout=5)
            process.stdout.close()
            process.stderr.close()

    def close(self):
        info = self.path.stat()
        if (info.st_dev, info.st_ino) != self.identity:
            raise RuntimeError("Owned fixture namespace was replaced; preserving it")
        run(["umount", str(self.path)], check=True)
        self.path.unlink()


class TargetView(host.SystemView):
    def __init__(self, fixture):
        super().__init__(fixture.root)
        self.fixture = fixture
        self.packages = pkg.AptBackend(fixture.root)

    def query(self, arguments):
        if arguments[0] == "ip":
            return 0, self.fixture.ip.command(arguments[1:])
        if arguments[0] == "systemctl":
            # This root is a copied Debian target, not a second system manager.
            # Its files and native parsers are real; service ownership is the
            # explicitly supported ifupdown fixture contract.
            unit = arguments[-1]
            return 0, "LoadState=loaded\nActiveState=active\n" if unit == "networking.service" else "LoadState=not-found\nActiveState=inactive\n"
        result = self.packages.command(arguments)
        return result["returncode"], result["output"]


class BaseFixture:
    def __init__(self, *, broken_source=False, delayed_install=False, timeout=120):
        kernel.require_container()
        self.global_hostname = socket.gethostname()
        self.kernel = kernel.Fixture(timeout=timeout, ssh_targets=["198.51.100.20"], preserve_original=True)
        self.kernel.supervisor.recover(self.kernel.run_id)
        self.root, self.directory = self.kernel.root, self.kernel.directory
        shutil.copytree(TEMPLATE, self.root, symlinks=True, dirs_exist_ok=True)
        for name, minor in (("null", 3), ("zero", 5), ("random", 8), ("urandom", 9)):
            device = self.root / "dev" / name
            if not device.exists():
                os.mknod(device, stat.S_IFCHR | 0o666, os.makedev(1, minor))
        # Seed the explicitly supported regular-file fixture subset. Debian's
        # package-owned aliases are preserved in the template; no fixture write
        # may follow an absolute symlink into the container's own /etc.
        locale = self.root / "etc/default/locale"
        if locale.is_symlink():
            locale.unlink()
        shell_extra = self.root / "etc/profile.d/70-systemd-shell-extra.sh"
        if shell_extra.is_symlink():
            link = shell_extra.readlink()
            source = (self.root / str(link).lstrip("/") if link.is_absolute()
                      else shell_extra.parent / link).resolve()
            source.relative_to(self.root.resolve())
            content = source.read_bytes()
            shell_extra.unlink()
            shell_extra.write_bytes(content)
        self.write("/etc/hostname", "oldhost\n")
        self.write("/etc/hosts", "127.0.0.1 localhost\n127.0.1.1 oldhost alias\n::1 localhost\n")
        self.write("/etc/resolv.conf", "nameserver 192.0.2.53\n")
        self.write("/etc/default/locale", 'LANG="C.UTF-8"\n')
        self.write("/etc/timezone", "Europe/Berlin\n")
        localtime = self.root / "etc/localtime"
        localtime.unlink(missing_ok=True)
        localtime.symlink_to("/usr/share/zoneinfo/Europe/Berlin")
        self.write("/etc/network/interfaces", "auto lo ens3\niface lo inet loopback\n"
                   "iface ens3 inet static\n    address 192.0.2.10/32\n    pointopoint 198.51.100.1\n    gateway 198.51.100.1\n"
                   "iface ens3 inet6 static\n    address 2001:db8:1::10/64\n    gateway fe80::1\n")
        (self.root / "sys/class/net/ens3").mkdir(parents=True, exist_ok=True)
        if delayed_install:
            self.write("/etc/apt/apt.conf.d/rzandal-ci-delay", 'DPkg::Pre-Invoke { "echo $$ > /run/rzandal-ci-sleeper.pid; exec /bin/sleep 60"; };\n')
        self.uts = UTSFixture(self.directory)
        self.peer = SSHPeer(self.kernel)
        self.manager = self.kernel.manager
        self.supervisor = kernel.guard.RecoverySupervisor(self.manager)
        self.profile = bootstrap.Profile.from_dict({"schema_version": 1, "hostname": "rzandal-ci-base", "interface": "ens3",
                         "ipv4_cidr": "198.51.100.20/32", "ipv4_gateway": "198.51.100.1", "ipv6_enabled": False,
                         "user_timezone": "Europe/Moscow", "motd": False}, current_user="root")
        self.source = "deb [trusted=yes] file:/missing-rzandal-ci-repo ./" if broken_source else REPOSITORY
        self.timeout = timeout
        self.run_id = None

    def write(self, path, content):
        local = self.root / path.lstrip("/")
        local.parent.mkdir(parents=True, exist_ok=True)
        if local.is_symlink():
            raise RuntimeError("Fixture writes refuse symlink targets: " + path)
        local.write_text(content)

    def review(self):
        plan = bootstrap.build_plan(self.profile)
        plan["base"]["apt_sources"] = [self.source]  # Owned offline CI fixture only; no profile or CLI override.
        report = host.prepare_host_plan(self.profile, pwd.getpwuid(0), plan, bootstrap.merge_profile_timezone,
                                        view=TargetView(self.kernel))
        if report["blockers"]:
            raise AssertionError("Base fixture preflight: " + json.dumps(report["blockers"]))
        return base.prepare_review(self.profile, report, network=self.kernel.ip,
                                   hostname=base.HostnameBackend(self.root), packages=pkg.AptBackend(self.root),
                                   **getattr(self, "motd_review", {}))

    def launch(self):
        self.report = self.review()
        self.originals = {path: self.manager.fs.snapshot(path) for path in self.report["watched_files"]}
        self.run_id = base.launch_reviewed(self.manager, self.supervisor, self.report, refresh=self.review,
                         confirm=lambda question: "y", output=lambda text: None, timeout=self.timeout, namespace=self.kernel.namespace)
        self.kernel.run_id, self.kernel.supervisor = self.run_id, self.supervisor

    def applied(self):
        if self.manager.status(self.run_id)["phase"] != "applied":
            return False
        config = self.supervisor.load(self.run_id)
        return config["acknowledgment"]["phase"] == "waiting" and self.supervisor.packages(self.run_id, config).load()["phase"] == "completed"

    def start(self):
        self.launch()
        kernel.wait_for(self.applied, seconds=35)

    def rolled_back(self):
        return self.manager.status(self.run_id)["phase"] == "rolled_back"

    def retained(self):
        return self.supervisor.packages(self.run_id, self.supervisor.load(self.run_id)).load()

    def assert_restored(self):
        self.kernel.assert_restored()
        for path, before in self.originals.items():
            if not kernel.tx.same_file(self.manager.fs.snapshot(path), before):
                raise AssertionError("Original Base file not restored: " + path)
        if base.HostnameBackend(self.root).snapshot()["hostname"] != "base-before-ci":
            raise AssertionError("Original UTS fixture hostname not restored")
        if socket.gethostname() != self.global_hostname:
            raise AssertionError("Unrelated container hostname was changed")

    def close(self):
        try:
            self.kernel.close()
        finally:
            try:
                self.peer.close()
            finally:
                self.uts.close()


class NativeBaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        kernel.require_container()
        if not TEMPLATE.is_dir():
            raise RuntimeError("Native Base CI template is absent")

    def fixture(self, **options):
        fixture = BaseFixture(**options)
        self.addCleanup(fixture.close)
        return fixture

    def test_native_base_apt_hostname_fresh_ssh_and_second_run(self):
        fixture = self.fixture()
        fixture.start()
        self.assertIn("ccze", pkg.installed(pkg.AptBackend(fixture.root).inspect()))
        self.assertEqual(base.HostnameBackend(fixture.root).snapshot()["hostname"], "rzandal-ci-base")
        self.assertEqual(socket.gethostname(), fixture.global_hostname)
        self.assertEqual(pkg.AptBackend(fixture.root).command(["date", "+%Z"])["output"].strip(), "UTC")
        self.assertTrue(any(obj["kind"] == "address" and obj["cidr"] == "192.0.2.10/32" for obj in fixture.kernel.ip.snapshot()["objects"]))
        result = fixture.peer.acknowledge()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(any(obj["kind"] == "address" and obj["cidr"] == "192.0.2.10/32" for obj in fixture.kernel.ip.snapshot()["objects"]))
        healthy = fixture.kernel.ip.snapshot()
        fixture.supervisor.recover(fixture.run_id)
        self.assertEqual(fixture.kernel.ip.snapshot(), healthy)
        review = fixture.review()
        self.assertFalse(any(entry["changed"] for entry in review["files"]))
        fingerprints = {path: kernel.tx.fingerprint(fixture.manager.fs.snapshot(path)) for path in review["watched_files"]}
        fixture.start()
        self.assertEqual(fixture.manager._run(fixture.run_id)[0]["files"], [])
        self.assertEqual(fixture.retained()["steps"]["install"], "skipped")
        result = fixture.peer.acknowledge()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(fingerprints, {path: kernel.tx.fingerprint(fixture.manager.fs.snapshot(path)) for path in fingerprints})

    def test_failed_native_update_restores_all_settings_without_installing(self):
        fixture = self.fixture(broken_source=True)
        fixture.launch()
        kernel.wait_for(fixture.rolled_back, seconds=35)
        fixture.assert_restored()
        self.assertNotIn("ccze", pkg.installed(pkg.AptBackend(fixture.root).inspect()))
        self.assertEqual(fixture.retained()["steps"]["update"], "failed")
        self.assertEqual(fixture.retained()["steps"]["install"], "pending")

    def test_deadline_rollback_retains_the_native_installed_package(self):
        fixture = self.fixture(timeout=20)
        fixture.start()
        self.assertIn("ccze", pkg.installed(pkg.AptBackend(fixture.root).inspect()))
        kernel.wait_for(fixture.rolled_back, seconds=35)
        fixture.assert_restored()
        self.assertIn("ccze", pkg.installed(pkg.AptBackend(fixture.root).inspect()))
        self.assertEqual(fixture.retained()["phase"], "retained")
        self.assertFalse(fixture.retained()["manual_attention"])

    def test_sigkill_while_native_apt_waits_stops_its_child_and_restores(self):
        fixture = self.fixture(delayed_install=True)
        fixture.launch()
        marker = fixture.root / "run/rzandal-ci-sleeper.pid"
        kernel.wait_for(marker.is_file, seconds=30)
        child = int(marker.read_text().strip())
        started = kernel.guard.ssh.parse_stat(Path(f"/proc/{child}/stat").read_text())["start_ticks"]
        self.assertEqual(fixture.retained()["steps"]["install"], "intent")
        fixture.supervisor.systemd.command("kill", "--signal=SIGKILL", "--kill-whom=all", kernel.guard.unit_names(fixture.run_id)["apply"])
        kernel.wait_for(fixture.rolled_back, seconds=30)
        fixture.assert_restored()
        record = Path(f"/proc/{child}/stat")
        self.assertTrue(not record.exists() or kernel.guard.ssh.parse_stat(record.read_text())["start_ticks"] != started)
        self.assertNotIn("ccze", pkg.installed(pkg.AptBackend(fixture.root).inspect()))
        self.assertFalse(fixture.retained()["manual_attention"])


if __name__ == "__main__":
    unittest.main()
