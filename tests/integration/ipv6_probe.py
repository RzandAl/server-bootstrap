"""Real temporary IPv6 paths through owned router/external namespaces."""

import copy
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import unittest
import uuid

import kernel_recovery as kernel

# kernel_recovery loaded the protected-root project module via recovery.
probe = kernel.guard.probe
CONFIG = {"cidr": "2001:db8:2::20/64", "gateway": "fe80::1",
          "targets": [{"address": "2001:db8:ffff::100", "port": 8443}, {"address": "2001:db8:ffff::101", "port": 8053}]}


def command(arguments, **options):
    try:
        return subprocess.run(arguments, capture_output=True, text=True, timeout=15, **options)
    except subprocess.CalledProcessError as error:
        raise RuntimeError(f"Fixture command {error.cmd!r} failed: {error.stderr.strip()}") from error


SERVER_CODE = r'''
import json, selectors, socket, sys
selector = selectors.DefaultSelector()
for address, port in (("2001:db8:ffff::100", 8443), ("2001:db8:ffff::101", 8053)):
    server = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((address, port)); server.listen(); server.setblocking(False)
    selector.register(server, selectors.EVENT_READ)
open(sys.argv[2], "w").write("ready\n")
while True:
    for key, _ in selector.select():
        client, peer = key.fileobj.accept()
        with open(sys.argv[1], "a") as stream:
            stream.write(json.dumps({"source": peer[0], "target": client.getsockname()[0]}) + "\n")
        client.close()
'''


class RoutedPeer:
    def __init__(self, fixture):
        kernel.require_container()
        self.fixture = fixture
        self.router = "rzandal-test-" + uuid.uuid4().hex[:16]
        self.external = "rzandal-test-" + uuid.uuid4().hex[:16]
        self.received = fixture.directory / "received.jsonl"
        self.ready = fixture.directory / "external-ready"
        for namespace in (self.router, self.external):
            command(["ip", "netns", "add", namespace], check=True)
            self.ip(namespace, ["link", "set", "lo", "up"])
        fixture.ip.command(["link", "set", "peer0", "netns", self.router])
        self.ip(self.router, ["link", "add", "wan0", "type", "veth", "peer", "name", "ext0"])
        self.ip(self.router, ["link", "set", "ext0", "netns", self.external])
        for namespace, interface in ((self.router, "peer0"), (self.router, "wan0"), (self.external, "ext0")):
            self.ip(namespace, ["link", "set", interface, "up"])
        for namespace, address, interface in (
            (self.router, "fe80::1/64", "peer0"), (self.router, "2001:db8:1::1/64", "peer0"),
            (self.router, "2001:db8:2::1/64", "peer0"), (self.router, "2001:db8:fffe::1/64", "wan0"),
            (self.external, "2001:db8:fffe::2/64", "ext0"), (self.external, "2001:db8:ffff::100/128", "lo"),
            (self.external, "2001:db8:ffff::101/128", "lo"),
        ):
            self.ip(namespace, ["-6", "address", "add", address, "dev", interface, "nodad"])
        self.ip(self.router, ["-6", "route", "add", "2001:db8:ffff::/64", "via", "2001:db8:fffe::2", "dev", "wan0"])
        for subnet in ("2001:db8:1::/64", "2001:db8:2::/64"):
            self.ip(self.external, ["-6", "route", "add", subnet, "via", "2001:db8:fffe::1", "dev", "ext0"])
        command(["ip", "netns", "exec", self.router, "sysctl", "-w", "net.ipv6.conf.all.forwarding=1"], check=True)
        self.server = subprocess.Popen(["ip", "netns", "exec", self.external, "/usr/bin/python3", "-I", "-c", SERVER_CODE,
                                        str(self.received), str(self.ready)], stdout=subprocess.DEVNULL,
                                       stderr=subprocess.PIPE, text=True, start_new_session=True)
        kernel.wait_for(lambda: self.ready.is_file())

    @staticmethod
    def ip(namespace, arguments):
        return command(["ip", "-n", namespace, *arguments], check=True)

    def firewall(self, *, block_candidate=False, block_echo=False):
        forward = "ip6 saddr 2001:db8:2::/64 drop" if block_candidate else ""
        echo = "icmpv6 type echo-request drop" if block_echo else ""
        text = ("table inet rzandal_probe_test {\n"
                "chain forward {\n type filter hook forward priority 0; policy accept;\n" + forward + "\n}\n"
                "chain input {\n type filter hook input priority 0; policy accept;\n" + echo + "\n}\n}\n")
        command(["ip", "netns", "exec", self.router, "nft", "-f", "-"], input=text, check=True)

    def sources(self):
        return [json.loads(line)["source"] for line in self.received.read_text().splitlines()] if self.received.is_file() else []

    def close(self):
        if self.server.poll() is None:
            os.killpg(self.server.pid, signal.SIGTERM)
            self.server.wait(timeout=5)
        self.server.stderr.close()
        for namespace in (self.external, self.router):
            command(["ip", "netns", "delete", namespace], check=True)


class IPv6ProbeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        kernel.require_container()

    def fixture(self, *, gateway="fe80::1", preexisting=False, timeout=60):
        config = {**copy.deepcopy(CONFIG), "gateway": gateway}
        fixture = kernel.Fixture(timeout, ipv6_probe=config, ipv6_preexisting=preexisting)
        try:
            peer = RoutedPeer(fixture)
        except BaseException:
            fixture.close()
            raise
        def cleanup():
            try:
                fixture.close()
            except BaseException:
                participant = self.participant(fixture)
                print("PROBE_DIAGNOSTICS " + json.dumps(participant.load(), sort_keys=True), file=sys.stderr)
                for args in (["-j", "link", "show", "dev", "ens3"], ["-j", "-6", "address", "show", "dev", "ens3"],
                             ["-j", "-6", "route", "show", "table", "all"], ["-j", "-6", "rule", "show"]):
                    print("KERNEL_DIAGNOSTICS " + json.dumps(args) + " " + fixture.ip.command(args), file=sys.stderr)
                raise
            finally:
                peer.close()
        self.addCleanup(cleanup)
        return fixture, peer

    def participant(self, fixture):
        return fixture.supervisor.ipv6_probe(fixture.run_id, fixture.supervisor.load(fixture.run_id))

    def assert_cleaned(self, fixture):
        participant = self.participant(fixture)
        value = participant.load()
        self.assertEqual(participant.backend.current_routes(value["allocation"]), [])
        self.assertIsNone(participant.backend.current_rule(value["config"], value["allocation"]))
        self.assertTrue(all(not entry["owned"] or entry["phase"] in {"pending", "undone"} for entry in value["operations"]))

    def restored(self, fixture):
        return fixture.manager.status(fixture.run_id)["phase"] == "rolled_back"

    def test_link_local_gateway_echo_blocked_but_marked_candidate_tcp_passes(self):
        fixture, peer = self.fixture()
        peer.firewall(block_echo=True)
        ping = command(["ip", "netns", "exec", fixture.namespace, "ping", "-6", "-n", "-I", "ens3", "-c", "1", "-W", "1", "fe80::1"])
        self.assertNotEqual(ping.returncode, 0)
        fixture.start()
        value = self.participant(fixture).load()
        self.assertEqual(value["phase"], "passed")
        self.assertEqual(value["result"]["source"], "2001:db8:2::20")
        kernel.wait_for(lambda: len(peer.sources()) >= 2)
        self.assertEqual(set(peer.sources()), {"2001:db8:2::20"})
        self.assert_cleaned(fixture)
        fixture.supervisor.recover(fixture.run_id)
        fixture.assert_restored()

    def test_global_in_prefix_gateway_and_reused_ipv6_keep_original_address(self):
        fixture, peer = self.fixture(gateway="2001:db8:2::1", preexisting=True)
        fixture.start()
        self.assertTrue(self.participant(fixture).load()["reused"])
        self.assert_cleaned(fixture)
        fixture.supervisor.recover(fixture.run_id)
        fixture.assert_restored()

    def test_global_in_prefix_gateway_with_new_candidate_address(self):
        fixture, peer = self.fixture(gateway="2001:db8:2::1")
        fixture.start()
        self.assertFalse(self.participant(fixture).load()["reused"])
        self.assertEqual(self.participant(fixture).load()["phase"], "passed")
        self.assert_cleaned(fixture)
        fixture.supervisor.recover(fixture.run_id)
        fixture.assert_restored()

    def test_actual_duplicate_address_fails_before_any_permanent_file(self):
        fixture, peer = self.fixture()
        peer.ip(peer.router, ["-6", "address", "add", "2001:db8:2::20/64", "dev", "peer0", "nodad"])
        fixture.supervisor.start(fixture.run_id)
        kernel.wait_for(lambda: self.restored(fixture), seconds=25)
        self.assertFalse(self.participant(fixture).load()["result"]["passed"])
        self.assertIn("duplicate", self.participant(fixture).load()["result"]["error"])
        self.assert_cleaned(fixture)
        fixture.assert_restored()

    def test_old_working_ipv6_cannot_mask_an_unreachable_candidate_source(self):
        fixture, peer = self.fixture()
        peer.firewall(block_candidate=True)
        backend = probe.ProbeBackend("ens3", namespace=fixture.namespace)
        old = probe.TCPConnector().connect(backend, "2001:db8:1::10", CONFIG["targets"][0], 0)
        self.assertTrue(old["connected"])
        fixture.supervisor.start(fixture.run_id)
        kernel.wait_for(lambda: self.restored(fixture), seconds=30)
        value = self.participant(fixture).load()
        self.assertFalse(value["result"]["passed"])
        self.assertEqual(set(peer.sources()), {"2001:db8:1::10"})
        self.assert_cleaned(fixture)
        fixture.assert_restored()

    def test_sigkill_during_probe_cleans_rule_routes_and_address(self):
        fixture, peer = self.fixture()
        peer.firewall(block_candidate=True)
        fixture.supervisor.start(fixture.run_id)
        participant = self.participant(fixture)
        kernel.wait_for(lambda: participant.load()["operations"][-1]["phase"] == "done", seconds=15)
        fixture.supervisor.systemd.command("kill", "--signal=SIGKILL", "--kill-whom=all", kernel.guard.unit_names(fixture.run_id)["apply"])
        kernel.wait_for(lambda: self.restored(fixture), seconds=25)
        self.assert_cleaned(fixture)
        fixture.assert_restored()

    def test_passed_clean_probe_can_commit_without_late_recovery_undo(self):
        fixture, peer = self.fixture()
        fixture.start()
        self.assert_cleaned(fixture)
        fixture.supervisor.commit_fixture(fixture.run_id, verify=lambda: True)
        healthy = fixture.ip.settled()
        fixture.supervisor.recover(fixture.run_id)
        self.assertEqual(fixture.ip.settled(), healthy)
        self.assertEqual(fixture.sentinel.read_text(), "candidate\n")


if __name__ == "__main__":
    unittest.main()
