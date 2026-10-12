"""Runs only in the disposable Debian/systemd CI container, never on a user's VPS."""

import copy
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
import transaction as tx
import network_recovery as net
import recovery as guard


def require_container():
    if (os.environ.get("RZANDAL_RECOVERY_CI") != "1" or not Path("/.dockerenv").is_file()
            or Path("/proc/1/comm").read_text().strip() != "systemd"):
        raise RuntimeError("Integration requires the named disposable systemd CI container")


def wait_for(predicate, seconds=20):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.15)
    raise AssertionError("Integration condition did not complete before timeout")


class Fixture:
    def __init__(self, timeout=30):
        require_container()
        self.namespace = "rzandal-test-" + uuid.uuid4().hex[:16]
        self.directory = Path(tempfile.mkdtemp(prefix="rzandal-ci-", dir="/srv"))
        self.root = self.directory / "host"
        (self.root / "etc").mkdir(parents=True)
        self.sentinel = self.root / "etc/bootstrap-sentinel"
        self.sentinel.write_text("original\n")
        self.manager = tx.FileTransaction(root=self.root)
        self.ip = net.IPBackend("ens3", namespace=self.namespace)
        subprocess.run(["ip", "netns", "add", self.namespace], check=True)
        self.ip.command(["link", "add", "ens3", "type", "veth", "peer", "name", "peer0"])
        self.ip.command(["link", "set", "peer0", "up"])
        self.ip.command(["link", "set", "ens3", "up"])
        self.ip.command(["-4", "address", "add", "192.0.2.10/32", "dev", "ens3"])
        self.ip.command(["-4", "route", "add", "198.51.100.1/32", "dev", "ens3", "scope", "link", "proto", "static"])
        self.ip.command(["-4", "route", "add", "default", "via", "198.51.100.1", "dev", "ens3", "src", "192.0.2.10", "proto", "static"])
        self.ip.command(["-6", "address", "add", "2001:db8:1::10/64", "dev", "ens3"])
        self.ip.command(["-6", "route", "add", "default", "via", "fe80::1", "dev", "ens3", "proto", "static", "metric", "1024"])
        self.before = self.ip.settled()
        before = tx.fingerprint(self.manager.fs.snapshot("/etc/bootstrap-sentinel"))
        after = tx.regular(b"candidate\n", 0o644, 0, 0)
        after["content"] = "candidate\n"
        del after["data"]
        self.report = {"file_plan_available": True, "blockers": [], "watched_files": {"/etc/bootstrap-sentinel": before},
                       "watched_patterns": {}, "facts": {},
                       "files": [{"path": "/etc/bootstrap-sentinel", "before": before, "after": after, "changed": True}]}
        self.run_id = self.manager.prepare(self.report, refresh=lambda: copy.deepcopy(self.report))
        old_address = next(obj for obj in self.before["objects"] if obj["kind"] == "address" and obj["family"] == 4)
        old_default = next(obj for obj in self.before["objects"] if obj["kind"] == "route" and obj["dst"] == "0.0.0.0/0")
        old_v6_default = next(obj for obj in self.before["objects"] if obj["kind"] == "route" and obj["dst"] == "::/0")
        self.operations = [
            {"action": "add", "object": {"kind": "address", "family": 4, "cidr": "198.51.100.20/32"}},
            {"action": "add", "object": {"kind": "address", "family": 6, "cidr": "2001:db8:2::20/64"}},
            {"action": "add", "object": old_v6_default},
            {"action": "delete", "object": old_default},
            {"action": "add", "object": {**old_default, "src": "198.51.100.20"}},
            {"action": "delete", "object": old_address},
        ]
        self.supervisor = guard.RecoverySupervisor(self.manager)
        self.supervisor.arm(self.run_id, self.report, interface="ens3", namespace=self.namespace,
                            operations=self.operations, timeout=timeout)

    def applied(self):
        config = self.supervisor.load(self.run_id)
        return self.supervisor.network(self.run_id, config).load()["phase"] == "applied"

    def start(self):
        self.supervisor.start(self.run_id)
        wait_for(self.applied)

    def assert_restored(self):
        if self.sentinel.read_text() != "original\n" or self.ip.settled() != self.before:
            raise AssertionError("Original file, IPv4/IPv6 addresses, and main routes were not restored")

    def close(self):
        if self.manager.status(self.run_id)["phase"] not in tx.FINAL_PHASES:
            if self.manager.status(self.run_id).get("supervised"):
                self.supervisor.recover(self.run_id)
            else:
                self.manager.recover(self.run_id)
        subprocess.run(["ip", "netns", "delete", self.namespace], check=True)


class RuntimeRecoveryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        require_container()

    def fixture(self, timeout=30):
        fixture = Fixture(timeout)
        self.addCleanup(fixture.close)
        return fixture

    def test_real_worker_and_manual_recovery_restore_both_families(self):
        fixture = self.fixture()
        fixture.start()
        self.assertEqual(fixture.sentinel.read_text(), "candidate\n")
        fixture.supervisor.recover(fixture.run_id)
        fixture.assert_restored()

    def test_real_deadline_restores_after_client_process_exits(self):
        fixture = self.fixture(timeout=7)
        # Launch from a separate client process which exits before rollback.
        code = """
import sys
from pathlib import Path
sys.path.insert(0, '/opt/bootstrap')
import transaction as tx
import recovery as guard
manager = tx.FileTransaction(root=Path(sys.argv[1]))
guard.RecoverySupervisor(manager).start(sys.argv[2])
"""
        result = subprocess.run([sys.executable, "-I", "-c", code, str(fixture.root), fixture.run_id],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        wait_for(lambda: fixture.manager.status(fixture.run_id)["phase"] == "rolled_back", seconds=20)
        fixture.assert_restored()

    def test_sigkill_of_owned_worker_triggers_onfailure_recovery(self):
        fixture = self.fixture()
        # Stop the owned worker while it waits for DAD after an address intent.
        names = guard.unit_names(fixture.run_id)
        config = fixture.supervisor.load(fixture.run_id)
        fixture.supervisor.start(fixture.run_id)
        # Catch the service while it is waiting for IPv6 DAD after journaling an
        # address addition. OnFailure must recover even a partial network step.
        journal = fixture.supervisor.network(fixture.run_id, config)
        wait_for(lambda: any(entry["phase"] == "intent" for entry in journal.load()["operations"]), seconds=10)
        fixture.supervisor.systemd.command("kill", "--signal=SIGKILL", "--kill-whom=all", names["apply"])
        wait_for(lambda: fixture.manager.status(fixture.run_id)["phase"] == "rolled_back", seconds=20)
        fixture.assert_restored()

    def test_fixture_commit_disarms_real_timer_and_preserves_candidate(self):
        fixture = self.fixture(timeout=7)
        fixture.start()
        fixture.supervisor.commit_fixture(fixture.run_id, verify=lambda: True)
        expected = fixture.ip.settled()
        # Late explicit recovery must observe committed state and do nothing.
        fixture.supervisor.recover(fixture.run_id)
        self.assertEqual(fixture.sentinel.read_text(), "candidate\n")
        self.assertEqual(fixture.ip.settled(), expected)

    def test_in_prefix_ipv4_and_point_to_point_peer_restore(self):
        fixture = self.fixture()
        fixture.supervisor.recover(fixture.run_id)
        # A new run records /24 and /32 peer address semantics against the kernel.
        fixture.ip.command(["-4", "address", "add", "203.0.113.10/24", "broadcast", "203.0.113.255", "dev", "ens3"])
        fixture.ip.command(["-4", "address", "add", "192.0.2.30/32", "peer", "198.51.100.2/32", "dev", "ens3"])
        before = fixture.ip.settled()
        fingerprint = tx.fingerprint(fixture.manager.fs.snapshot("/etc/bootstrap-sentinel"))
        fixture.report["watched_files"]["/etc/bootstrap-sentinel"] = fingerprint
        fixture.report["files"][0]["before"] = fingerprint
        fixture.run_id = fixture.manager.prepare(fixture.report, refresh=lambda: fixture.report)
        # Use a low-level journal under the same lock, still inside the fixture namespace.
        journal = net.NetworkJournal(fixture.manager, fixture.run_id, fixture.ip)
        with fixture.manager._lock():
            addresses = [obj for obj in before["objects"] if obj["kind"] == "address" and obj["family"] == 4 and obj["cidr"] != "192.0.2.10/32"]
            journal.prepare_locked([{"action": "delete", "object": obj} for obj in addresses])
            journal.apply_locked()
            journal.recover_locked()
        self.assertEqual(fixture.ip.settled(), before)
        fixture.manager.recover(fixture.run_id)


def prepare_boot():
    fixture = Fixture(timeout=90)
    fixture.start()
    fixture.manager._save("/boot-fixture.json", {"run_id": fixture.run_id, "root": str(fixture.root)})
    print(fixture.run_id)


def verify_boot():
    require_container()
    manager = tx.FileTransaction()
    value = manager._load("/boot-fixture.json")
    manager = tx.FileTransaction(root=Path(value["root"]))
    wait_for(lambda: manager.status(value["run_id"])["phase"] == "rolled_back")
    assert (Path(value["root"]) / "etc/bootstrap-sentinel").read_text() == "original\n"
    supervisor = guard.RecoverySupervisor(manager)
    config = supervisor.load(value["run_id"])
    assert supervisor.network(value["run_id"], config).load()["phase"] == "expired_on_boot"
    print("PASS: manager restart restored original files before network startup; obsolete kernel state was not replayed")


if __name__ == "__main__":
    if sys.argv[1:] == ["prepare-boot"]:
        prepare_boot()
    elif sys.argv[1:] == ["verify-boot"]:
        verify_boot()
    else:
        unittest.main()
