"""Real OpenSSH TCP connections between owned disposable network namespaces."""

import json
import os
from pathlib import Path
import pwd
import signal
import subprocess
import sys
import unittest
from unittest import mock
import uuid

import kernel_recovery as kernel


def run(arguments, **options):
    return subprocess.run(arguments, capture_output=True, text=True, timeout=15, **options)


class SSHPeer:
    def __init__(self, fixture):
        kernel.require_container()
        self.fixture = fixture
        self.namespace = "rzandal-test-" + uuid.uuid4().hex[:16]
        self.directory = fixture.directory / "ssh"
        self.directory.mkdir(mode=0o755)
        fixture.directory.chmod(0o755)
        private = self.directory / "private"
        private.mkdir(mode=0o700)
        self.client_key, host_key = private / "client", private / "host"
        for key in (self.client_key, host_key):
            result = run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)])
            if result.returncode:
                raise RuntimeError(result.stderr)
        authorized = self.directory / "authorized_keys"
        authorized.write_text(self.client_key.with_suffix(".pub").read_text())
        authorized.chmod(0o644)
        host_public = run(["ssh-keygen", "-y", "-f", str(host_key)], check=True).stdout.strip()
        self.known_hosts = self.directory / "known_hosts"
        self.known_hosts.write_text("".join(f"[{target}]:2222 {host_public}\n" for target in
                                           ("192.0.2.10", "198.51.100.20", "2001:db8:2::20")))
        config = self.directory / "sshd_config"
        config.write_text(f"""Port 2222
ListenAddress 0.0.0.0
ListenAddress ::
HostKey {host_key}
PidFile {self.directory / 'sshd.pid'}
AuthorizedKeysFile {authorized}
PermitRootLogin prohibit-password
PasswordAuthentication no
KbdInteractiveAuthentication no
UsePAM yes
UseDNS no
StrictModes yes
AllowUsers root rzandal-ci-user rzandal-ci-other
AllowTcpForwarding no
X11Forwarding no
PermitUserEnvironment no
""")
        Path("/run/sshd").mkdir(mode=0o755, exist_ok=True)
        run(["/usr/sbin/sshd", "-t", "-f", str(config)], check=True)
        run(["ip", "netns", "add", self.namespace], check=True)
        fixture.ip.command(["link", "set", "peer0", "netns", self.namespace])
        for arguments in (["link", "set", "lo", "up"], ["link", "set", "peer0", "up"],
                          ["-4", "address", "add", "192.0.2.100/32", "dev", "peer0"],
                          ["-6", "address", "add", "2001:db8:ffff::100/128", "dev", "peer0"],
                          ["-4", "route", "add", "192.0.2.10/32", "dev", "peer0"],
                          ["-4", "route", "add", "198.51.100.20/32", "dev", "peer0"],
                          ["-6", "route", "add", "2001:db8:2::20/128", "dev", "peer0"]):
            run(["ip", "-n", self.namespace, *arguments], check=True)
        # The client has its own DAD lifecycle; server readiness alone does not
        # establish that its IPv6 source address is usable yet.
        kernel.net.IPBackend("peer0", namespace=self.namespace).settled()
        self.log = (self.directory / "server.log").open("wb")
        self.server = subprocess.Popen(["ip", "netns", "exec", fixture.namespace, "/usr/sbin/sshd", "-D", "-e", "-f", str(config)],
                                       stdout=subprocess.DEVNULL, stderr=self.log, start_new_session=True)
        self.controls = []
        kernel.wait_for(lambda: self.command(":", target="192.0.2.10").returncode == 0, seconds=10)

    def arguments(self, user, target):
        return ["ip", "netns", "exec", self.namespace, "ssh", "-p", "2222", "-i", str(self.client_key),
                "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "ConnectTimeout=8",
                "-o", "StrictHostKeyChecking=yes", "-o", f"UserKnownHostsFile={self.known_hosts}",
                f"{user}@{target}"]

    def command(self, command, *, user="root", target="198.51.100.20", control=None):
        arguments = self.arguments(user, target)
        arguments[-1:-1] = ["-S", str(control) if control else "none", "-o", "ControlMaster=no"]
        if control:
            # A refused/missing multiplex channel must not fall back to a new
            # TCP transport and turn this refusal scenario into a fresh login.
            arguments[-1:-1] = ["-o", "ProxyCommand=/bin/false"]
        result = run([*arguments, command])
        if result.returncode == 255:
            # Only owned fixture namespaces are inspected. No keys are printed.
            diagnostics = []
            for namespace in (self.namespace, self.fixture.namespace):
                for kind in ("address", "route", "neighbour"):
                    diagnostics.append(run(["ip", "-n", namespace, "-j", "-6", kind, "show"]).stdout.strip())
            result.stderr += "\nOwned IPv6 transport diagnostics: " + json.dumps(diagnostics) + "\n"
        return result

    def master(self, target="198.51.100.20"):
        control = self.directory / ("control-" + uuid.uuid4().hex[:8])
        arguments = self.arguments("root", target)
        # -M after ControlMaster=yes toggles it to the interactive 'ask' mode.
        arguments[-1:-1] = ["-S", str(control), "-o", "ControlMaster=yes", "-Nf"]
        result = run(arguments)
        if result.returncode:
            raise AssertionError(result.stderr)
        self.controls.append((control, target))
        return control

    def acknowledge(self, *, user="root", **options):
        command = f"/usr/bin/python3 -I /opt/bootstrap/recovery.py acknowledge {self.fixture.run_id}"
        if user != "root":
            command = "unset SSH_CONNECTION; sudo -n " + command
        return self.command(command, user=user, **options)

    def close(self):
        for control, target in self.controls:
            arguments = self.arguments("root", target)
            arguments[-1:-1] = ["-S", str(control), "-O", "exit"]
            run(arguments)
        if self.server.poll() is None:
            os.killpg(self.server.pid, signal.SIGTERM)
            self.server.wait(timeout=5)
        self.log.close()
        run(["ip", "netns", "delete", self.namespace], check=True)


class FreshSSHTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        kernel.require_container()
        for name in ("rzandal-ci-user", "rzandal-ci-other"):
            run(["useradd", "--create-home", "--shell", "/bin/sh", name], check=True)
        sudoers = Path("/etc/sudoers.d/rzandal-bootstrap-ci")
        sudoers.write_text("".join(f"{name} ALL=(root) NOPASSWD: /usr/bin/python3 -I /opt/bootstrap/recovery.py acknowledge *\n"
                                   for name in ("rzandal-ci-user", "rzandal-ci-other")))
        sudoers.chmod(0o440)
        run(["visudo", "-c", "-f", str(sudoers)], check=True)

    def fixture(self, *, timeout=60, candidate_preexisting=False, account=None):
        environment = {}
        if account is not None:
            entry = pwd.getpwnam(account)
            environment = {"SUDO_UID": str(entry.pw_uid), "SUDO_GID": str(entry.pw_gid), "SUDO_USER": account}
        # Match the future caller policy while fixture preparation runs in CI's
        # console. Actual acknowledgment must authenticate this user over SSH.
        with mock.patch.dict(os.environ, environment):
            fixture = kernel.Fixture(timeout, ssh_targets=["198.51.100.20", "2001:db8:2::20"],
                                     preserve_original=True, candidate_preexisting=candidate_preexisting)
        try:
            peer = SSHPeer(fixture)
        except BaseException:
            fixture.close()
            raise
        def close():
            # Removing the client's veth namespace removes ens3 as well. Restore
            # the fixture while that interface and the SSH transport still exist.
            try:
                fixture.close()
            finally:
                peer.close()
        self.addCleanup(close)
        return fixture, peer

    def assert_success(self, result):
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["phase"], "committed")

    def assert_guarded(self, fixture, result):
        self.assertEqual(result.returncode, 2, result.stderr)
        config = fixture.supervisor.load(fixture.run_id)
        self.assertTrue(fixture.supervisor.systemd.active(config["units"]["timer"]))
        self.assertEqual(fixture.manager.status(fixture.run_id)["phase"], "applied")

    def test_real_fresh_ipv4_connection_commits_and_disarms_timer(self):
        fixture, peer = self.fixture()
        fixture.start()
        self.assert_success(peer.acknowledge())
        config = fixture.supervisor.load(fixture.run_id)
        self.assertEqual(config["acknowledgment"]["evidence"]["connection"]["client_address"], "192.0.2.100")
        self.assertEqual(config["acknowledgment"]["phase"], "acknowledged")
        self.assertFalse(fixture.supervisor.systemd.active(config["units"]["timer"]))
        self.assert_success(peer.acknowledge())

    def test_real_fresh_ipv6_connection_uses_the_candidate_address(self):
        fixture, peer = self.fixture()
        fixture.start()
        self.assert_success(peer.acknowledge(target="2001:db8:2::20"))
        config = fixture.supervisor.load(fixture.run_id)
        self.assertEqual(config["acknowledgment"]["evidence"]["connection"]["server_address"], "2001:db8:2::20")

    def test_old_controlmaster_transport_is_rejected_but_new_transport_succeeds(self):
        fixture, peer = self.fixture(candidate_preexisting=True)
        control = peer.master()
        fixture.start()
        result = peer.acknowledge(control=control)
        self.assert_guarded(fixture, result)
        self.assertIn("new SSH connection", result.stderr)
        self.assert_success(peer.acknowledge())

    def test_old_address_wrong_account_and_forged_environment_cannot_disarm(self):
        fixture, peer = self.fixture()
        fixture.start()
        self.assert_guarded(fixture, peer.acknowledge(target="192.0.2.10"))
        self.assert_guarded(fixture, peer.acknowledge(user="rzandal-ci-other"))
        forged = peer.command(f"SSH_CONNECTION='192.0.2.100 12345 198.51.100.20 2222' /usr/bin/python3 -I /opt/bootstrap/recovery.py acknowledge {fixture.run_id}")
        self.assert_guarded(fixture, forged)
        self.assert_success(peer.acknowledge())

    def test_real_sudo_caller_without_ssh_environment_hint_is_authenticated(self):
        fixture, peer = self.fixture(account="rzandal-ci-user")
        fixture.start()
        self.assert_success(peer.acknowledge(user="rzandal-ci-user"))
        config = fixture.supervisor.load(fixture.run_id)
        self.assertEqual(config["acknowledgment"]["evidence"]["account"]["name"], "rzandal-ci-user")

    def test_unacknowledged_old_transport_times_out_and_restores_originals(self):
        fixture, peer = self.fixture(timeout=12, candidate_preexisting=True)
        control = peer.master()
        fixture.start()
        self.assert_guarded(fixture, peer.acknowledge(control=control))
        kernel.wait_for(lambda: fixture.manager.status(fixture.run_id)["phase"] == "rolled_back", seconds=20)
        fixture.assert_restored()


if __name__ == "__main__":
    unittest.main()
