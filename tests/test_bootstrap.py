"""Regression tests for validated plans and preservation of existing state."""

import contextlib
import copy
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import bootstrap as app


EXAMPLE = {
    "schema_version": 1,
    "hostname": "rzandal-host-edge",
    "interface": "ens3",
    "user": "razis",
    "ipv4_cidr": "192.0.2.10/32",
    "ipv4_gateway": "198.51.100.1",
    "ipv6_enabled": True,
    "ipv6_cidr": "2001:db8:1234::2/64",
    "ipv6_gateway": "2001:db8:1234::1",
    "user_timezone": "Europe/Moscow",
    "motd": True,
}


class ProfileTests(unittest.TestCase):
    def profile(self, **changes):
        return app.Profile.from_dict({**EXAMPLE, **changes})

    def test_previous_ipv6_typo_is_rejected(self):
        with self.assertRaisesRegex(app.ValidationError, "invalid IPv6"):
            self.profile(ipv6_cidr="22a12:bec4:1bb0:1c13::2/64")

    def test_full_ip_validation_rejects_malformed_and_wrong_family_values(self):
        for field, values in {
            "ipv4_cidr": ["999.0.2.10/32", "192.0.2.10/33", "192.0.2.10", "2001:db8::2/64",
                          "192.0.2.10/255.255.255.0", "192.0.2.10/0", "01.2.3.4/24"],
            "ipv6_cidr": ["2001:db8::2/129", "2001:db8::1::2/64", "192.0.2.10/24",
                          "::/64", "fe80::2/64", "ff02::1/64", "::ffff:192.0.2.10/128"],
            "ipv4_gateway": ["2001:db8::1", "0.0.0.0", "127.0.0.1", "255.255.255.255"],
            "ipv6_gateway": ["192.0.2.1", "::1", "fe80::1%ens3", "2001:db8::1/64"],
        }.items():
            for value in values:
                with self.subTest(field=field, value=value), self.assertRaises(app.ValidationError):
                    self.profile(**{field: value})

    def test_canonicalizes_addresses_without_changing_prefix(self):
        profile = self.profile(ipv6_cidr="2001:0DB8:1234:0000:0000:0000:0000:0002/064")
        self.assertEqual(profile.ipv6_cidr, "2001:db8:1234::2/64")

    def test_off_link_ipv4_gateway_is_accepted_and_reported(self):
        plan = app.build_plan(self.profile())
        self.assertTrue(plan["base"]["ipv4_gateway_off_link"])
        self.assertIn("explicit gateway route", app.format_plan(plan))

    def test_in_prefix_gateway_does_not_require_off_link_route(self):
        plan = app.build_plan(self.profile(ipv4_cidr="192.0.2.10/24", ipv4_gateway="192.0.2.1"))
        self.assertFalse(plan["base"]["ipv4_gateway_off_link"])

    def test_network_broadcast_and_self_gateways_are_rejected(self):
        for changes in (
            {"ipv4_cidr": "192.0.2.0/24"}, {"ipv4_cidr": "192.0.2.255/24"},
            {"ipv4_cidr": "192.0.2.10/24", "ipv4_gateway": "192.0.2.0"},
            {"ipv4_cidr": "192.0.2.10/24", "ipv4_gateway": "192.0.2.255"},
            {"ipv4_gateway": "192.0.2.10"}, {"ipv6_gateway": "2001:db8:1234::2"},
        ):
            with self.subTest(changes=changes), self.assertRaises(app.ValidationError):
                self.profile(**changes)

    def test_point_to_point_prefix_is_valid(self):
        profile = self.profile(ipv4_cidr="192.0.2.0/31", ipv4_gateway="192.0.2.1")
        self.assertEqual(profile.ipv4_cidr, "192.0.2.0/31")

    def test_ipv6_link_local_gateway_keeps_interface_separate(self):
        plan = app.build_plan(self.profile(ipv6_gateway="fe80::1"))
        self.assertEqual(plan["base"]["ipv6_gateway"], "fe80::1")
        self.assertFalse(plan["base"]["ipv6_gateway_off_link"])

    def test_off_link_global_ipv6_gateway_requires_provider_review(self):
        plan = app.build_plan(self.profile(ipv6_gateway="2001:db8:5678::1"))
        self.assertTrue(plan["base"]["ipv6_gateway_off_link"])

    def test_disabled_ipv6_drops_ipv6_dns_and_rejects_stale_values(self):
        profile = self.profile(ipv6_enabled=False, ipv6_cidr=None, ipv6_gateway=None)
        plan = app.build_plan(profile)
        self.assertEqual(plan["base"]["dns"], ["1.1.1.1", "9.9.9.10"])
        self.assertIsNone(plan["base"]["ipv6"])
        with self.assertRaises(app.ValidationError):
            self.profile(ipv6_enabled=False)

    def test_strict_json_rejects_unknown_fields_wrong_types_and_schema(self):
        for changes in ({"firewall": True}, {"ipv6_enabled": "false"}, {"motd": 1},
                        {"schema_version": True}, {"schema_version": 2}, {"hostname": None}):
            with self.subTest(changes=changes), self.assertRaises(app.ValidationError):
                self.profile(**changes)

    def test_duplicate_json_keys_are_rejected(self):
        with self.assertRaisesRegex(app.ValidationError, "duplicate JSON key"):
            json.loads('{"schema_version":1,"motd":false,"motd":true}',
                       object_pairs_hook=app.reject_duplicate_keys)

    def test_shell_sensitive_names_and_timezone_paths_are_rejected(self):
        for field, values in {
            "hostname": ["-host", "host-", "bad_name", "host.example", "h" * 64, "host\nother"],
            "interface": ["lo", "ens3;id", "ens3$(id)", "../ens3", "x" * 16],
            "user": ["-root", "SomeUser", "razis;id", "user name", "x" * 33],
            "user_timezone": ["../../etc/passwd", "/etc/passwd", "Europe/Moscow;id", "Moon/Base"],
        }.items():
            for value in values:
                with self.subTest(field=field, value=value), self.assertRaises(app.ValidationError):
                    self.profile(**{field: value})

    def test_planning_is_repeatable_and_does_not_mutate_input(self):
        original = copy.deepcopy(EXAMPLE)
        profile = app.Profile.from_dict(EXAMPLE)
        first = app.build_plan(profile)
        self.assertEqual(first, app.build_plan(profile))
        self.assertEqual(EXAMPLE, original)
        self.assertFalse(first["apply_available"])
        self.assertFalse(first["modules"]["firewall"]["selected"])
        self.assertFalse(first["modules"]["vpn"]["selected"])
        self.assertEqual(first["modules"]["motd"]["source_ref"], app.MOTD_SOURCE_REF)


class ProfileBlockTests(unittest.TestCase):
    def test_second_run_preserves_bytes_and_single_block(self):
        original = '# user settings\nexport PATH="$HOME/bin:$PATH"\n'
        once = app.merge_profile_timezone(original, "Europe/Moscow")
        twice = app.merge_profile_timezone(once, "Europe/Moscow")
        self.assertEqual(once, twice)
        self.assertTrue(twice.startswith(original))
        self.assertEqual(twice.count(app.PROFILE_BEGIN), 1)

    def test_timezone_update_preserves_content_before_and_after_block(self):
        prefix = "# user prefix\n"
        suffix = "# user suffix\nexport EDITOR=vim\n"
        original = prefix + app.profile_timezone_block("UTC") + suffix
        expected = prefix + app.profile_timezone_block("Europe/Moscow") + suffix
        self.assertEqual(app.merge_profile_timezone(original, "Europe/Moscow"), expected)

    def test_empty_file_and_file_without_final_newline_remain_repeatable(self):
        for original in ("", "export EDITOR=vim"):
            once = app.merge_profile_timezone(original, "UTC")
            self.assertEqual(once, app.merge_profile_timezone(once, "UTC"))

    def test_malformed_markers_do_not_silently_discard_content(self):
        for original in (
            app.PROFILE_BEGIN + "\nkeep me\n",
            app.PROFILE_END + "\nkeep me\n",
            app.PROFILE_END + "\nkeep me\n" + app.PROFILE_BEGIN + "\n",
            app.profile_timezone_block("UTC") * 2,
        ):
            with self.subTest(original=original), self.assertRaises(app.ValidationError):
                app.merge_profile_timezone(original, "Europe/Moscow")


class DiscoveryTests(unittest.TestCase):
    @staticmethod
    def query(arguments):
        if arguments == ["address", "show"]:
            return [
                {"ifname": "ens3", "addr_info": [{"family": "inet", "scope": "global",
                                                  "local": "192.0.2.10", "prefixlen": 32}]},
                {"ifname": "ens4", "addr_info": []},
            ]
        if arguments == ["-4", "route", "show", "default"]:
            return [{"dev": "ens4", "gateway": "198.51.100.1"}]
        if arguments == ["route", "get", "203.0.113.20"]:
            return [{"dev": "ens3"}]
        return []

    def test_ssh_client_route_takes_priority_over_another_default_route(self):
        with mock.patch.dict(os.environ, {"SSH_CONNECTION": "203.0.113.20 50000 192.0.2.10 22"}), \
                mock.patch.object(app, "read_ip_json", side_effect=self.query):
            values = app.detect_defaults()
        self.assertEqual(values["interface"], "ens3")
        self.assertEqual(values["ipv4_cidr"], "192.0.2.10/32")
        self.assertEqual(values["ipv4_gateway"], "")

    def test_ambiguous_interfaces_and_addresses_are_not_guessed(self):
        address_data = [
            {"ifname": "ens3", "addr_info": []}, {"ifname": "ens4", "addr_info": []},
        ]
        with mock.patch.dict(os.environ, {"SSH_CONNECTION": ""}), \
                mock.patch.object(app, "read_ip_json", side_effect=lambda a: address_data if a == ["address", "show"] else []):
            values = app.detect_defaults()
        self.assertEqual(values["interface"], "")
        self.assertEqual(values["ipv4_cidr"], "")

    def test_tentative_ipv6_is_not_proposed_as_working_address(self):
        address_data = [{"ifname": "ens3", "addr_info": [
            {"family": "inet6", "scope": "global", "local": "2001:db8::2",
             "prefixlen": 64, "tentative": True},
        ]}]
        with mock.patch.dict(os.environ, {"SSH_CONNECTION": ""}), \
                mock.patch.object(app, "read_ip_json", side_effect=lambda a: address_data if a == ["address", "show"] else []):
            values = app.detect_defaults()
        self.assertEqual(values["interface"], "ens3")
        self.assertIsNone(values["ipv6_cidr"])


class CliTests(unittest.TestCase):
    def test_wizard_reprompts_invalid_ipv6_before_producing_plan(self):
        defaults = {**EXAMPLE, "ipv6_enabled": False}
        answers = ["", "", "", "", "", "y", "22a12::2/64", "2001:db8:1234::2/64", "", "", ""]
        stdout, stderr = io.StringIO(), io.StringIO()
        with mock.patch.object(app, "detect_defaults", return_value=defaults), \
                mock.patch.object(app.Path, "is_dir", return_value=True), \
                mock.patch("builtins.input", side_effect=answers), \
                contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            profile = app.collect_profile()
        self.assertEqual(profile.ipv6_cidr, "2001:db8:1234::2/64")
        self.assertIn("invalid IPv6", stderr.getvalue())

    def test_changing_interface_does_not_reuse_other_interfaces_addresses(self):
        defaults = copy.deepcopy(EXAMPLE)
        answers = ["", "ens4", "", "203.0.113.10/24", "203.0.113.1", "n", "", "n"]
        with mock.patch.object(app, "detect_defaults", return_value=defaults), \
                mock.patch.object(app.Path, "is_dir", return_value=True), \
                mock.patch("builtins.input", side_effect=answers), \
                contextlib.redirect_stdout(io.StringIO()):
            profile = app.collect_profile()
        self.assertEqual(profile.interface, "ens4")
        self.assertEqual(profile.ipv4_cidr, "203.0.113.10/24")
        self.assertEqual(profile.ipv4_gateway, "203.0.113.1")
        self.assertIsNone(profile.ipv6_cidr)

    def test_json_plan_reads_profile_without_external_commands_or_file_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory, "server.json")
            config.write_text(json.dumps(EXAMPLE))
            before = config.read_bytes()
            stdout = io.StringIO()
            with mock.patch.object(app.subprocess, "run", side_effect=AssertionError("unexpected command")), \
                    contextlib.redirect_stdout(stdout):
                status = app.main(["--config", str(config), "--json"])
            self.assertEqual(status, 0)
            plan = json.loads(stdout.getvalue())
            self.assertFalse(plan["apply_available"])
            self.assertEqual(config.read_bytes(), before)
            self.assertEqual([path.name for path in Path(directory).iterdir()], ["server.json"])

    def test_invalid_profile_has_nonzero_status_without_partial_plan(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory, "server.json")
            config.write_text(json.dumps({**EXAMPLE, "ipv6_cidr": "22a12::2/64"}))
            stdout, stderr = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                status = app.main(["--config", str(config), "--json"])
            self.assertEqual(status, 2)
            self.assertEqual(stdout.getvalue(), "")
            self.assertIn("invalid IPv6", stderr.getvalue())

    def test_apply_option_is_unavailable(self):
        result = subprocess.run([sys.executable, str(Path(app.__file__)), "--apply"],
                                capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 2)
        self.assertIn("unrecognized arguments: --apply", result.stderr)


if __name__ == "__main__":
    unittest.main()
