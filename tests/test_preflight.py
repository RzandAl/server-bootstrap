"""Host-audit regressions using isolated filesystem and read-only query fixtures."""

import contextlib
from dataclasses import replace
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import bootstrap as app
import preflight as host
from test_bootstrap import EXAMPLE


ACCOUNT = SimpleNamespace(pw_name="razis", pw_uid=1000, pw_gid=1000,
                          pw_dir="/home/razis", pw_shell="/bin/bash")
ROOT = SimpleNamespace(pw_name="root", pw_uid=0, pw_gid=0,
                       pw_dir="/root", pw_shell="/bin/bash")


class InvokingAccountTests(unittest.TestCase):
    def account(self, uid, euid, environment):
        def lookup(number):
            if number == 0:
                return ROOT
            if number == 1000:
                return ACCOUNT
            raise KeyError(number)
        with mock.patch.dict(os.environ, environment, clear=True), \
                mock.patch.object(app.os, "getuid", return_value=uid), \
                mock.patch.object(app.os, "geteuid", return_value=euid), \
                mock.patch.object(app.pwd, "getpwuid", side_effect=lookup):
            return app.invoking_account()

    def test_direct_root_and_direct_user_use_passwd_not_shell_variables(self):
        self.assertIs(self.account(0, 0, {"USER": "razis", "HOME": "/home/other"}), ROOT)
        self.assertIs(self.account(1000, 1000, {"USER": "root", "LOGNAME": "other"}), ACCOUNT)

    def test_sudo_targets_the_consistent_original_account(self):
        self.assertIs(self.account(0, 0, {"SUDO_UID": "1000", "SUDO_GID": "1000", "SUDO_USER": "razis"}), ACCOUNT)

    def test_unprivileged_process_cannot_select_another_account_with_sudo_environment(self):
        self.assertIs(self.account(1000, 1000, {"SUDO_UID": "0", "SUDO_GID": "0", "SUDO_USER": "root"}), ACCOUNT)

    def test_partial_unknown_or_inconsistent_sudo_identity_is_rejected(self):
        for environment in ({"SUDO_USER": "razis"},
                            {"SUDO_UID": "-1", "SUDO_GID": "1000", "SUDO_USER": "razis"},
                            {"SUDO_UID": "1000", "SUDO_GID": "0", "SUDO_USER": "razis"},
                            {"SUDO_UID": "1000", "SUDO_GID": "1000", "SUDO_USER": "root"},
                            {"SUDO_UID": "9999", "SUDO_GID": "1000", "SUDO_USER": "razis"}):
            with self.subTest(environment=environment), self.assertRaises(app.ValidationError):
                self.account(0, 0, environment)

    def test_profile_user_is_an_optional_assertion_not_an_account_selector(self):
        values = {key: value for key, value in EXAMPLE.items() if key != "user"}
        self.assertEqual(app.Profile.from_dict(values, current_user="root").user, "root")
        self.assertEqual(app.Profile.from_dict(EXAMPLE, current_user="razis").user, "razis")
        with self.assertRaisesRegex(app.ValidationError, "invoking account"):
            app.Profile.from_dict(EXAMPLE, current_user="root")


class FixtureView(host.SystemView):
    def __init__(self, root):
        super().__init__(root)
        self.packages = {"ifupdown", "iproute2", "tzdata", "ca-certificates", "debian-archive-keyring"}
        self.services = {}
        self.calls = []
        self.addresses = [{"ifname": "ens3", "link_type": "ether", "addr_info": [
            {"family": "inet", "scope": "global", "local": "192.0.2.10", "prefixlen": 32},
        ]}]
        self.rules = [{"priority": 0, "table": "local"}, {"priority": 32766, "table": "main"},
                      {"priority": 32767, "table": "default"}]
        self.fail_packages = False

    def file(self, path):
        state = super().file(path)
        if state.kind != "absent":
            uid = 1000 if path.startswith("/home/razis/") else 0
            state = replace(state, uid=uid, gid=uid)
            self.files[path] = state
        return state

    def available(self, command):
        return True

    def query(self, arguments):
        self.calls.append(arguments)
        if arguments == ["locale", "-a"]:
            return 0, "C\nC.utf8\nPOSIX\n"
        if arguments[0] == "dpkg-query":
            return int(self.fail_packages), "".join(f"{package}\tii \n" for package in sorted(self.packages))
        if arguments[0] == "systemctl":
            unit = arguments[-1]
            state = self.services.get(unit, "active" if unit == "networking.service" else "inactive")
            load = "loaded" if unit == "networking.service" or unit in self.services else "not-found"
            return 0, f"LoadState={load}\nActiveState={state}\n"
        if arguments[:3] == ["ip", "-j", "address"]:
            return 0, json.dumps(self.addresses)
        if arguments[:3] == ["ip", "-j", "route"]:
            return 0, '[{"dev":"ens3","prefsrc":"192.0.2.10"}]'
        if arguments[0] == "ip" and "rule" in arguments:
            return 0, json.dumps(self.rules)
        if arguments[0] == "ip" and "route" in arguments:
            return 0, '[{"dst":"default","gateway":"198.51.100.1","dev":"ens3"}]' if "-4" in arguments else "[]"
        raise AssertionError(f"Unexpected non-read-only query: {arguments}")


class HostPlanTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.write("/etc/os-release", 'ID=debian\nVERSION_ID="13"\nVERSION_CODENAME=trixie\n')
        self.write("/etc/hostname", "oldhost\n")
        self.write("/etc/hosts", "127.0.0.1 localhost\n127.0.1.1 oldhost oldhost.example alias\n::1 localhost ip6-localhost\n")
        self.write("/etc/resolv.conf", "nameserver 192.0.2.53\n")
        self.write("/etc/default/locale", 'LANG="en_US.UTF-8"\nLC_TIME="ru_RU.UTF-8"\n')
        self.write("/etc/timezone", "Europe/Berlin\n")
        self.write("/usr/share/zoneinfo/UTC", "fixture zoneinfo")
        self.write("/home/razis/.profile", '# user content\nexport EDITOR=vim\n')
        self.write("/etc/network/interfaces", "# main\nsource interfaces.d/*\nauto lo ens3 ens4\niface lo inet loopback\niface ens4 inet manual\n")
        self.write("/etc/network/interfaces.d/primary", "# provider interface\niface ens3 inet static\n    address 192.0.2.10/32\n    gateway 198.51.100.1\n    mtu 1450\n")
        self.write("/etc/apt/sources.list", "# Debian\ndeb http://deb.debian.org/debian trixie main\n")
        self.write("/etc/apt/sources.list.d/debian.sources", "Types: deb deb-src\nURIs: https://deb.debian.org/debian\nSuites: trixie trixie-updates\nComponents: main\nSigned-By: /usr/share/keyrings/debian-archive-keyring.gpg\n")
        self.write("/etc/apt/sources.list.d/vendor.list", "# custom vendor\ndeb [signed-by=/etc/apt/keyrings/vendor.gpg] https://packages.example.invalid/debian stable main\n")
        self.root.joinpath("sys/class/net/ens3").mkdir(parents=True)
        self.view = FixtureView(self.root)
        self.profile = app.Profile.from_dict(EXAMPLE, current_user="razis")

    def write(self, path, content):
        local = self.root / path.lstrip("/")
        local.parent.mkdir(parents=True, exist_ok=True)
        local.write_text(content)

    def report(self, **profile_changes):
        profile = app.Profile.from_dict({**EXAMPLE, **profile_changes}, current_user="razis")
        with mock.patch.dict(os.environ, {"SSH_CONNECTION": "203.0.113.20 50000 192.0.2.10 22"}):
            return host.prepare_host_plan(profile, ACCOUNT, app.build_plan(profile), app.merge_profile_timezone, view=self.view)

    def snapshot(self):
        return {str(path.relative_to(self.root)): (path.read_bytes(), path.stat().st_mtime_ns)
                for path in self.root.rglob("*") if path.is_file() and not path.is_symlink()}

    def test_full_plan_preserves_target_bytes_and_reports_exact_candidates(self):
        before = self.snapshot()
        report = self.report()
        self.assertEqual(report["blockers"], [])
        self.assertEqual(self.snapshot(), before)
        self.assertFalse(report["apply_available"])
        self.assertFalse(report["connectivity_validated"])
        files = {item["path"]: item for item in report["files"]}
        primary = files["/etc/network/interfaces"]["after"]["content"]
        self.assertIn("auto lo ens4\n", primary)
        self.assertIn("iface ens4 inet manual\n", primary)
        self.assertIn("pointopoint 198.51.100.1\n", primary)
        self.assertIn("    mtu 1450\n", primary)
        self.assertEqual(primary.count("iface ens3 inet static"), 1)
        self.assertEqual(primary.count("iface ens3 inet6 static"), 1)
        self.assertNotIn("iface ens3", files["/etc/network/interfaces.d/primary"]["after"]["content"])
        vendor = files["/etc/apt/sources.list.d/vendor.list"]
        self.assertFalse(vendor["changed"])
        self.assertEqual(vendor["after"]["content"], self.view.file(vendor["path"]).text())
        self.assertNotIn("LC_TIME", files["/etc/default/locale"]["after"]["content"])
        self.assertIn("alias", files["/etc/hosts"]["after"]["content"])
        self.assertIn("export EDITOR=vim", files["/home/razis/.profile"]["after"]["content"])

    def test_extended_attributes_block_file_plan_without_losing_metadata(self):
        path = self.root / "etc/hostname"
        try:
            os.setxattr(path, "user.rzandal-fixture", b"preserve me")
        except OSError as error:
            self.skipTest(f"Fixture filesystem does not support user xattrs: {error}")
        before = self.snapshot()
        report = self.report()
        self.assertTrue(any("extended attributes" in blocker for blocker in report["blockers"]))
        self.assertEqual(report["files"], [])
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(os.getxattr(path, "user.rzandal-fixture"), b"preserve me")

    def test_simulated_application_produces_no_changes_on_second_plan(self):
        first = self.report()
        self.assertFalse(first["blockers"])
        for item in first["files"]:
            local = self.root / item["path"].lstrip("/")
            if item["after"]["kind"] == "symlink":
                if local.exists() or local.is_symlink():
                    local.unlink()
                local.symlink_to(item["after"]["target"])
            else:
                self.write(item["path"], item["after"]["content"])
        self.view = FixtureView(self.root)
        second = self.report()
        self.assertEqual(second["blockers"], [])
        self.assertFalse(any(item["changed"] for item in second["files"]))

    def test_generated_or_symlinked_dns_blocks_all_staging(self):
        for symlink in (False, True):
            path = self.root / "etc/resolv.conf"
            path.unlink()
            if symlink:
                path.symlink_to("/run/systemd/resolve/stub-resolv.conf")
            else:
                self.write("/etc/resolv.conf", "# Generated by provider\nnameserver 192.0.2.53\n")
            self.view = FixtureView(self.root)
            report = self.report()
            self.assertTrue(report["blockers"])
            self.assertEqual(report["files"], [])

    def test_cloud_init_active_managers_and_resolver_packages_are_explicit_blockers(self):
        for package, unit in (("cloud-init", None), ("resolvconf", None), (None, "NetworkManager.service"),
                              (None, "systemd-networkd.service"), (None, "systemd-resolved.service")):
            self.view = FixtureView(self.root)
            if package:
                self.view.packages.add(package)
            if unit:
                self.view.services[unit] = "active"
            with self.subTest(package=package, unit=unit):
                report = self.report()
                self.assertTrue(report["blockers"])
                self.assertFalse(report["file_plan_available"])

    def test_conflicting_user_timezone_locale_and_bash_startup_are_not_silently_rewritten(self):
        for path, content in (("/home/razis/.profile", "export TZ=UTC\n"),
                              ("/home/razis/.profile", "export LC_TIME=ru_RU.UTF-8\n"),
                              ("/home/razis/.bash_profile", '. "$HOME/.profile"\n')):
            with self.subTest(path=path, content=content):
                self.write(path, content)
                self.view = FixtureView(self.root)
                report = self.report()
                self.assertTrue(report["blockers"])
                self.assertEqual(self.view.file(path).text(), content)
            if path.endswith(".bash_profile"):
                (self.root / path.lstrip("/")).unlink()
            self.write("/home/razis/.profile", "# user content\n")

    def test_source_directory_filters_names_and_supports_relative_paths(self):
        self.write("/etc/network/interfaces", "source-directory interfaces.d\nauto lo\niface lo inet loopback\n")
        self.write("/etc/network/interfaces.d/ignored.cfg", "mapping ens3\n script /bad\n")
        report = self.report()
        self.assertEqual(report["blockers"], [])
        self.assertNotIn("/etc/network/interfaces.d/ignored.cfg", report["watched_files"])
        self.assertIn("/etc/network/interfaces.d/*", report["watched_patterns"])

    def test_symlinked_source_directory_and_invalid_mtu_are_blocked(self):
        self.write("/etc/network/interfaces", "source-directory interfaces.d\n")
        directory = self.root / "etc/network/interfaces.d"
        directory.rename(directory.with_name("other"))
        directory.symlink_to("other")
        self.assertTrue(self.report()["blockers"])
        directory.unlink()
        directory.with_name("other").rename(directory)
        self.write("/etc/network/interfaces.d/primary", "iface ens3 inet static\n address 192.0.2.10/32\n mtu 999999\n")
        self.view = FixtureView(self.root)
        self.assertTrue(self.report()["blockers"])

    def test_diff_marks_missing_final_newline(self):
        self.write("/etc/hostname", "oldhost")
        report = self.report()
        self.assertFalse(report["blockers"])
        item = next(item for item in report["files"] if item["path"] == "/etc/hostname")
        self.assertIn("-oldhost\n\\ No newline at end of file\n+", item["diff"])

    def test_include_cycles_symlinks_mappings_hooks_and_dhcp_are_blocked(self):
        for content in ("source /etc/network/interfaces\n", "mapping ens3\n script /bad\n",
                        "iface ens3 inet dhcp\n", "iface ens3 inet static\n pre-up touch /tmp/should-not-run\n",
                        "auto /ens*\n", "iface ens3 inet static # inline comment\n"):
            self.write("/etc/network/interfaces", content)
            self.view = FixtureView(self.root)
            report = self.report()
            self.assertTrue(report["blockers"], content)
            self.assertFalse((self.root / "tmp/should-not-run").exists())

    def test_duplicate_stanzas_and_multiple_global_addresses_require_review(self):
        self.write("/etc/network/interfaces.d/extra", "iface ens3 inet static\n address 192.0.2.11/32\n")
        self.assertTrue(self.report()["blockers"])
        (self.root / "etc/network/interfaces.d/extra").unlink()
        self.view = FixtureView(self.root)
        self.view.addresses[0]["addr_info"].append({"family":"inet", "scope":"global", "local":"192.0.2.11", "prefixlen":32})
        self.assertTrue(self.report()["blockers"])

    def test_custom_routing_failed_inventory_and_wrong_os_block_staging(self):
        self.view.rules.append({"table": 100})
        self.assertTrue(self.report()["blockers"])
        self.view = FixtureView(self.root)
        self.view.fail_packages = True
        self.assertTrue(self.report()["blockers"])
        self.view = FixtureView(self.root)
        self.write("/etc/os-release", 'ID=debian\nVERSION_ID="12"\nVERSION_CODENAME=bookworm\n')
        self.assertTrue(self.report()["blockers"])

    def test_absent_manager_units_are_known_inactive_not_unknown(self):
        report = self.report()
        self.assertEqual(report["blockers"], [])
        self.assertEqual(report["facts"]["services"]["NetworkManager.service"], "not-installed")

    def test_ipv4_only_and_in_prefix_gateway_render_without_ipv6_or_peer(self):
        report = self.report(ipv4_cidr="192.0.2.10/24", ipv4_gateway="192.0.2.1",
                             ipv6_enabled=False, ipv6_cidr=None, ipv6_gateway=None)
        self.assertFalse(report["blockers"])
        files = {item["path"]: item for item in report["files"]}
        network = files["/etc/network/interfaces"]["after"]["content"]
        self.assertNotIn("pointopoint", network)
        self.assertNotIn("inet6", network)
        self.assertNotIn("2606:", files["/etc/resolv.conf"]["after"]["content"])

    def test_unsupported_off_link_gateway_shapes_block_the_candidate(self):
        for changes in ({"ipv4_cidr":"192.0.2.10/24"}, {"ipv6_gateway":"2001:db8:5678::1"}):
            with self.subTest(changes=changes):
                report = self.report(**changes)
                self.assertTrue(report["blockers"])
                self.assertEqual(report["files"], [])

    def test_profile_symlink_does_not_follow_or_modify_another_file(self):
        self.write("/home/razis/other", "untouched")
        path = self.root / "home/razis/.profile"
        path.unlink()
        path.symlink_to("other")
        report = self.report()
        self.assertTrue(report["blockers"])
        self.assertEqual((self.root / "home/razis/other").read_text(), "untouched")

    def test_cli_blocker_returns_nonzero_with_json_explanation_and_no_target_writes(self):
        self.write("/etc/cloud/cloud.cfg", "# provider configuration\n")
        config = self.root / "profile.json"
        config.write_text(json.dumps(EXAMPLE))
        before = self.snapshot()
        output = io.StringIO()
        with mock.patch.object(app, "invoking_account", return_value=ACCOUNT), \
                mock.patch.object(host, "SystemView", return_value=self.view), \
                contextlib.redirect_stdout(output):
            result = app.main(["--config", str(config), "--inspect", "--json"])
        self.assertEqual(result, 2)
        report = json.loads(output.getvalue())["host_plan"]
        self.assertTrue(report["blockers"])
        self.assertEqual(self.snapshot(), before)


class AptRendererTests(unittest.TestCase):
    def test_disabled_deb822_and_third_party_paragraphs_are_preserved(self):
        disabled = "Enabled: no\nTypes: deb\nURIs: https://deb.debian.org/debian\nSuites: bookworm\nComponents: main\n"
        vendor = "Types: deb\nURIs: https://packages.example.invalid/debian\nSuites: stable\nComponents: main\n"
        documents = {"/etc/apt/sources.list":"", "/etc/apt/sources.list.d/mixed.sources":disabled+"\n"+vendor}
        result = host.render_apt(documents, list(app.APT_SOURCES))
        self.assertEqual(result["/etc/apt/sources.list.d/mixed.sources"], disabled+"\n"+vendor)
        self.assertEqual(result, host.render_apt(result, list(app.APT_SOURCES)))

    def test_mixed_uris_duplicate_fields_and_nonstandard_suites_are_rejected(self):
        for text in ("Types: deb\nURIs: https://deb.debian.org/debian https://packages.example.invalid/debian\nSuites: trixie\n",
                     "Types: deb\nTypes: deb-src\nURIs: https://deb.debian.org/debian\nSuites: trixie\n",
                     "Types: deb\nURIs: https://deb.debian.org/debian\nSuites: trixie-backports\n"):
            with self.subTest(text=text), self.assertRaises(host.AuditError):
                host.render_apt({"/etc/apt/sources.list.d/test.sources":text}, list(app.APT_SOURCES))

    def test_official_legacy_options_and_deb_src_are_normalized_once(self):
        documents = {"/etc/apt/sources.list":"deb [arch=amd64 signed-by=/keyring.gpg] http://deb.debian.org/debian trixie main\ndeb-src https://deb.debian.org/debian trixie main\n"}
        result = host.render_apt(documents, list(app.APT_SOURCES))
        self.assertEqual(result["/etc/apt/sources.list"].count("deb https:"), 3)
        self.assertNotIn("deb-src", result["/etc/apt/sources.list"])
        self.assertEqual(result, host.render_apt(result, list(app.APT_SOURCES)))


class OtherPreservationTests(unittest.TestCase):
    def test_held_installed_packages_are_not_proposed_for_reinstallation(self):
        result = host.installed_packages("curl\thi \nifupdown\tii \nold-package\trc \n")
        self.assertEqual(result, {"curl", "ifupdown"})
        with self.assertRaisesRegex(host.AuditError, "reinstall-required"):
            host.installed_packages("curl\tiiR\n")

    def test_hostname_change_preserves_aliases_and_replaces_fqdn_and_short_name(self):
        result = host.render_hosts("127.0.0.1 localhost\n127.0.1.1 oldhost oldhost.example alias # keep\n", "oldhost.example", "newhost")
        self.assertEqual(result, "127.0.0.1 localhost\n127.0.1.1\tnewhost alias # keep\n")
        self.assertEqual(result, host.render_hosts(result, "newhost", "newhost"))

    def test_query_ignores_user_controlled_path_and_command_environment(self):
        with mock.patch.dict(os.environ, {"PATH":"/tmp/untrusted", "DPKG_ROOT":"/tmp/other"}), \
                mock.patch.object(host.shutil, "which", return_value="/usr/bin/dpkg-query"), \
                mock.patch.object(host.subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout="")) as run:
            host.SystemView().query(["dpkg-query", "-W"])
        self.assertEqual(run.call_args.args[0][0], "/usr/bin/dpkg-query")
        self.assertEqual(run.call_args.kwargs["env"], {"PATH":host.SYSTEM_PATH, "LC_ALL":"C"})


class IfupdownSyntaxTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("ifquery"), "ifquery is required for the Debian syntax check")
    def test_generated_dual_stack_and_off_link_v4_are_accepted_by_ifquery(self):
        profile = app.Profile.from_dict(EXAMPLE, current_user="razis")
        candidate = host.render_network({"/etc/network/interfaces":"auto lo\niface lo inet loopback\n"}, {}, app.build_plan(profile)["base"])["/etc/network/interfaces"]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "interfaces")
            path.write_text(candidate)
            result = subprocess.run(["ifquery", "--interfaces", str(path), "ens3"], capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("pointopoint: 198.51.100.1", result.stdout)
        self.assertIn("address: 2001:db8:1234::2\n", result.stdout)
        self.assertIn("netmask: 64\n", result.stdout)
        self.assertIn("netmask: 255.255.255.255\n", result.stdout)


if __name__ == "__main__":
    unittest.main()
