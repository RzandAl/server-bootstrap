"""Read-only planning foundation for RzandAl Server Bootstrap.

This development build collects and validates settings. It has no apply path.
Only the Python standard library is required; no package installation occurs.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import socket
import shutil
import subprocess
import sys
from dataclasses import dataclass
from typing import Any, Callable
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


SYSTEM_LOCALE = "C.UTF-8"
SYSTEM_TIMEZONE = "UTC"
DEFAULT_USER_TIMEZONE = "Europe/Moscow"
DEFAULT_INTERFACE = "ens3"
DNS_IPV4 = ("1.1.1.1", "9.9.9.10")
DNS_IPV6 = ("2606:4700:4700::1111",)
IPV6_PROBE_TARGETS = (("2606:4700:4700::1111", 443), ("2620:fe::10", 53))
BASE_PACKAGES = (
    "curl", "git", "rsync", "jq", "unzip", "htop", "mtr-tiny", "tcpdump", "ccze",
)
MOTD_REPOSITORY = "RzandAl/debian-server-info-motd"
MOTD_SOURCE_REF = "v0.3.1"
APT_SOURCES = (
    "deb https://deb.debian.org/debian trixie main non-free-firmware",
    "deb https://security.debian.org/debian-security trixie-security main non-free-firmware",
    "deb https://deb.debian.org/debian trixie-updates main non-free-firmware",
)
PROFILE_BEGIN = "# >>> RzandAl Server Bootstrap >>>"
PROFILE_END = "# <<< RzandAl Server Bootstrap <<<"
PROFILE_KEYS = {
    "schema_version", "hostname", "interface", "user", "ipv4_cidr",
    "ipv4_gateway", "ipv6_enabled", "ipv6_cidr", "ipv6_gateway",
    "user_timezone", "motd",
}


class ValidationError(ValueError):
    """A configuration value cannot be used in a bootstrap plan."""


def invoking_account() -> pwd.struct_passwd:
    """Resolve the real caller from passwd, including a consistent sudo identity.

    USER, LOGNAME and HOME are not account authorities. Sudo metadata is used
    only by a root process and must agree with the passwd entry for SUDO_UID.
    """
    uid = os.getuid()
    if os.geteuid() == 0 and any(key in os.environ for key in ("SUDO_UID", "SUDO_USER", "SUDO_GID")):
        raw_uid = os.environ.get("SUDO_UID", "")
        raw_gid = os.environ.get("SUDO_GID", "")
        if not re.fullmatch(r"[0-9]+", raw_uid) or not re.fullmatch(r"[0-9]+", raw_gid):
            raise ValidationError("user: incomplete or invalid sudo identity")
        uid = int(raw_uid)
        try:
            account = pwd.getpwuid(uid)
        except KeyError as error:
            raise ValidationError("user: sudo caller does not exist in passwd") from error
        if account.pw_name != os.environ.get("SUDO_USER") or account.pw_gid != int(raw_gid):
            raise ValidationError("user: sudo identity does not match passwd")
    try:
        account = pwd.getpwuid(uid)
    except KeyError as error:
        raise ValidationError("user: invoking UID does not exist in passwd") from error
    validate_user(account.pw_name)
    return account


def text_value(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValidationError(f"{name}: expected a nonempty string without surrounding whitespace")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValidationError(f"{name}: control characters are not allowed")
    return value


def validate_hostname(value: Any) -> str:
    value = text_value(value, "hostname").lower()
    if len(value) > 63 or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", value):
        raise ValidationError("hostname: use a short DNS label, 1–63 letters, digits or hyphens")
    return value


def validate_interface(value: Any) -> str:
    value = text_value(value, "interface")
    if len(value) > 15 or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", value) or value == "lo":
        raise ValidationError("interface: expected a non-loopback Linux interface name, up to 15 characters")
    return value


def validate_user(value: Any) -> str:
    value = text_value(value, "user")
    if len(value) > 32 or not re.fullmatch(r"[a-z_][a-z0-9_-]*", value):
        raise ValidationError("user: expected a lowercase Debian account name, up to 32 characters")
    return value


def validate_timezone(value: Any) -> str:
    value = text_value(value, "user_timezone")
    if (len(value) > 128 or not re.fullmatch(r"[A-Za-z0-9_+/-]+", value)
            or value.startswith("/") or ".." in value
            or value in {"localtime", "posixrules"}):
        raise ValidationError("user_timezone: expected an installed IANA timezone name")
    try:
        ZoneInfo(value)
    except (ZoneInfoNotFoundError, ValueError) as error:
        raise ValidationError(f"user_timezone: timezone is unavailable: {value}") from error
    return value


def parse_address(value: Any, family: int, name: str) -> Any:
    value = text_value(value, name)
    if "/" in value or "%" in value:
        raise ValidationError(f"{name}: enter a plain IPv{family} address; the interface is a separate field")
    try:
        address = ipaddress.ip_address(value)
    except ValueError as error:
        raise ValidationError(f"{name}: invalid IPv{family} address") from error
    if address.version != family:
        raise ValidationError(f"{name}: expected IPv{family}")
    if address.is_unspecified or address.is_multicast or address.is_loopback:
        raise ValidationError(f"{name}: expected a usable unicast address")
    if family == 4 and address == ipaddress.IPv4Address("255.255.255.255"):
        raise ValidationError(f"{name}: the limited broadcast address is not usable")
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        raise ValidationError(f"{name}: IPv4-mapped IPv6 addresses are outside the VPS profile")
    return address


def parse_cidr(value: Any, family: int, name: str) -> Any:
    value = text_value(value, name)
    pieces = value.split("/")
    if len(pieces) != 2 or not re.fullmatch(r"[0-9]{1,3}", pieces[1]):
        raise ValidationError(f"{name}: enter an address with a numeric CIDR prefix")
    address = parse_address(pieces[0], family, name)
    prefix = int(pieces[1])
    if not 1 <= prefix <= address.max_prefixlen:
        raise ValidationError(f"{name}: prefix must be between 1 and {address.max_prefixlen}")
    interface = ipaddress.ip_interface(f"{address}/{prefix}")
    if address.is_link_local:
        raise ValidationError(f"{name}: link-local addresses cannot be the static VPS address")
    if family == 4 and prefix < 31 and address in {
        interface.network.network_address, interface.network.broadcast_address,
    }:
        raise ValidationError(f"{name}: network and broadcast addresses cannot identify the VPS")
    return interface


def boolean_value(value: Any, name: str) -> bool:
    if type(value) is not bool:
        raise ValidationError(f"{name}: expected a JSON boolean")
    return value


@dataclass(frozen=True)
class Profile:
    hostname: str
    interface: str
    user: str
    ipv4_cidr: str
    ipv4_gateway: str
    ipv6_enabled: bool
    ipv6_cidr: str | None
    ipv6_gateway: str | None
    user_timezone: str
    motd: bool

    @classmethod
    def from_dict(cls, values: Any, *, current_user: str | None = None) -> Profile:
        if not isinstance(values, dict):
            raise ValidationError("profile: expected a JSON object")
        unknown = set(values) - PROFILE_KEYS
        if unknown:
            raise ValidationError(f"profile: unknown fields: {', '.join(sorted(unknown))}")
        if type(values.get("schema_version")) is not int or values["schema_version"] != 1:
            raise ValidationError("schema_version: expected integer 1")
        required = {"hostname", "interface", "ipv4_cidr", "ipv4_gateway"}
        missing = required - set(values)
        if missing:
            raise ValidationError(f"profile: missing fields: {', '.join(sorted(missing))}")
        ipv4 = parse_cidr(values["ipv4_cidr"], 4, "ipv4_cidr")
        gateway4 = parse_address(values["ipv4_gateway"], 4, "ipv4_gateway")
        if gateway4 == ipv4.ip:
            raise ValidationError("ipv4_gateway: gateway cannot be the VPS address")
        if ipv4.network.prefixlen < 31 and gateway4 in {
            ipv4.network.network_address, ipv4.network.broadcast_address,
        }:
            raise ValidationError("ipv4_gateway: network and broadcast addresses cannot be gateways")
        ipv6_enabled = boolean_value(values.get("ipv6_enabled", False), "ipv6_enabled")
        ipv6 = gateway6 = None
        if ipv6_enabled:
            ipv6 = parse_cidr(values.get("ipv6_cidr"), 6, "ipv6_cidr")
            gateway6 = parse_address(values.get("ipv6_gateway"), 6, "ipv6_gateway")
            if gateway6 == ipv6.ip:
                raise ValidationError("ipv6_gateway: gateway cannot be the VPS address")
        elif values.get("ipv6_cidr") is not None or values.get("ipv6_gateway") is not None:
            raise ValidationError("ipv6_enabled: disabled IPv6 must not retain address or gateway values")
        user = validate_user(current_user if current_user is not None else invoking_account().pw_name)
        if "user" in values and validate_user(values["user"]) != user:
            raise ValidationError("user: saved profile must match the invoking account; another account cannot be selected")
        return cls(
            validate_hostname(values["hostname"]), validate_interface(values["interface"]),
            user, str(ipv4), str(gateway4),
            ipv6_enabled, str(ipv6) if ipv6 else None, str(gateway6) if gateway6 else None,
            validate_timezone(values.get("user_timezone", DEFAULT_USER_TIMEZONE)),
            boolean_value(values.get("motd", True), "motd"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {"schema_version": 1, **self.__dict__}


def build_plan(profile: Profile) -> dict[str, Any]:
    ipv4 = ipaddress.ip_interface(profile.ipv4_cidr)
    gateway4 = ipaddress.ip_address(profile.ipv4_gateway)
    ipv6 = ipaddress.ip_interface(profile.ipv6_cidr) if profile.ipv6_cidr else None
    gateway6 = ipaddress.ip_address(profile.ipv6_gateway) if profile.ipv6_gateway else None
    return {
        "schema_version": 1,
        "mode": "preview",
        "apply_available": False,
        "ipv6_probe": {"cidr": profile.ipv6_cidr, "gateway": profile.ipv6_gateway,
                       "targets": [{"address": address, "port": port} for address, port in IPV6_PROBE_TARGETS]}
                      if profile.ipv6_enabled else None,
        "base": {
            "hostname": profile.hostname, "interface": profile.interface, "user": profile.user,
            "ipv4": profile.ipv4_cidr, "ipv4_gateway": profile.ipv4_gateway,
            "ipv4_gateway_off_link": gateway4 not in ipv4.network,
            "ipv6_enabled": profile.ipv6_enabled, "ipv6": profile.ipv6_cidr,
            "ipv6_gateway": profile.ipv6_gateway,
            "ipv6_gateway_off_link": bool(ipv6 and gateway6 and not gateway6.is_link_local
                                          and gateway6 not in ipv6.network),
            "dns": list(DNS_IPV4 + (DNS_IPV6 if profile.ipv6_enabled else ())),
            "locale": SYSTEM_LOCALE, "system_timezone": SYSTEM_TIMEZONE,
            "user_timezone": profile.user_timezone,
            "account_policy": "invoking-account",
            "apt_sources": list(APT_SOURCES),
            "packages": list(BASE_PACKAGES),
        },
        "modules": {
            "motd": {"selected": profile.motd, "repository": MOTD_REPOSITORY,
                     "source_ref": MOTD_SOURCE_REF, "apply_available": False},
            "firewall": {"selected": False, "status": "planned"},
            "vpn": {"selected": False, "status": "planned"},
        },
        "planned_managed_files": [
            "/etc/hostname", "/etc/hosts", "/etc/network/interfaces", "/etc/resolv.conf",
            "/etc/default/locale", "/etc/localtime", "/etc/timezone",
            f"~{profile.user}/.profile", "/etc/apt/sources.list",
        ],
        "required_before_apply": [
            "Inspect Debian version, invoking account, network and DNS ownership, and APT sources.",
            "Stage exact file changes and show the complete plan with one Apply? [y/N] confirmation.",
            "Back up changed files and arm an independent network rollback timer.",
            "Probe selected IPv6 after confirmation; clean up temporary state on every exit path.",
            "Apply atomically, verify connectivity from a new session, and commit recovery state.",
        ],
    }


def profile_timezone_block(timezone: str) -> str:
    timezone = validate_timezone(timezone)
    return f"{PROFILE_BEGIN}\nexport TZ={timezone}\n{PROFILE_END}\n"


def merge_profile_timezone(original: str, timezone: str) -> str:
    """Produce candidate .profile text without writing it or removing user content."""
    block = profile_timezone_block(timezone)
    lines = original.splitlines(keepends=True)
    starts = [i for i, line in enumerate(lines) if line.rstrip("\r\n") == PROFILE_BEGIN]
    ends = [i for i, line in enumerate(lines) if line.rstrip("\r\n") == PROFILE_END]
    if not starts and not ends:
        separator = "" if not original else ("\n" if original.endswith("\n") else "\n\n")
        return original + separator + block
    if len(starts) != 1 or len(ends) != 1 or starts[0] >= ends[0]:
        raise ValidationError(".profile: malformed or duplicate managed markers; preserve and review the file")
    return "".join(lines[:starts[0]]) + block + "".join(lines[ends[0] + 1:])


def read_ip_json(arguments: list[str]) -> list[dict[str, Any]]:
    """Run only read-only iproute2 queries, without shell evaluation."""
    try:
        executable = shutil.which("ip", path="/usr/sbin:/usr/bin:/sbin:/bin")
        if executable is None:
            return []
        result = subprocess.run(
            [executable, "-j", *arguments], check=True, capture_output=True, text=True, timeout=5,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
        )
        value = json.loads(result.stdout)
        return [entry for entry in value if isinstance(entry, dict)] if isinstance(value, list) else []
    except (OSError, subprocess.SubprocessError, ValueError):
        return []


def detect_defaults() -> dict[str, Any]:
    addresses = read_ip_json(["address", "show"])
    routes4 = read_ip_json(["-4", "route", "show", "default"])
    routes6 = read_ip_json(["-6", "route", "show", "default"])
    chosen = ""
    ssh_peer = os.environ.get("SSH_CONNECTION", "").split()
    if ssh_peer:
        try:
            peer = str(ipaddress.ip_address(ssh_peer[0]))
            route = read_ip_json(["route", "get", peer])
            if route:
                chosen = route[0].get("dev", "")
        except ValueError:
            pass
    if not chosen:
        route_interfaces = {route.get("dev") for route in routes4 if route.get("dev") != "lo"}
        route_interfaces.discard(None)
        if len(route_interfaces) == 1:
            chosen = route_interfaces.pop()
        else:
            interfaces = [entry.get("ifname") for entry in addresses if entry.get("ifname") != "lo"]
            if len(interfaces) == 1:
                chosen = interfaces[0]
    values: dict[str, Any] = {
        "schema_version": 1, "hostname": socket.gethostname().split(".")[0],
        "interface": chosen or "", "user": invoking_account().pw_name, "ipv4_cidr": "",
        "ipv4_gateway": "", "ipv6_enabled": False, "ipv6_cidr": None,
        "ipv6_gateway": None, "user_timezone": DEFAULT_USER_TIMEZONE, "motd": True,
    }
    for family, routes in ((4, routes4), (6, routes6)):
        candidates = [info for entry in addresses if entry.get("ifname") == chosen
                      for info in entry.get("addr_info", []) if info.get("scope") == "global"
                      and info.get("family") == ("inet" if family == 4 else "inet6")
                      and not info.get("tentative") and not info.get("dadfailed")
                      and not set(info.get("flags", [])) & {"tentative", "dadfailed"}]
        gateways = {entry["gateway"] for entry in routes if entry.get("dev") == chosen
                    and entry.get("gateway")}
        if len(candidates) == 1:
            info = candidates[0]
            values[f"ipv{family}_cidr"] = f"{info['local']}/{info['prefixlen']}"
        if len(gateways) == 1:
            values[f"ipv{family}_gateway"] = gateways.pop()
    return values


def ask(label: str, default: Any, validator: Callable[[str], Any]) -> Any:
    while True:
        answer = input(f"{label}" + (f" [{default}]" if default else "") + ": ").strip()
        if not answer:
            answer = str(default) if default is not None else ""
        try:
            return validator(answer)
        except ValidationError as error:
            print(f"Invalid value: {error}", file=sys.stderr)


def ask_yes_no(label: str, default: bool) -> bool:
    while True:
        answer = input(f"{label} [{'Y/n' if default else 'y/N'}]: ").strip().lower()
        if not answer:
            return default
        if answer in {"y", "yes", "д", "да"}:
            return True
        if answer in {"n", "no", "н", "нет"}:
            return False
        print("Please answer y or n.", file=sys.stderr)


def collect_profile() -> Profile:
    values = detect_defaults()
    account = invoking_account()
    values["user"] = account.pw_name
    detected_interface = values["interface"]
    print("RzandAl Server Bootstrap — planning preview\nNo system changes are made.\n")
    values["hostname"] = ask("Hostname (short name)", values["hostname"], validate_hostname)
    values["interface"] = ask("Primary interface", values["interface"], validate_interface)
    if not Path("/sys/class/net", values["interface"]).is_dir():
        raise ValidationError(f"interface: {values['interface']} does not exist on this host")
    # Do not reuse another interface's detected addresses or gateways.
    if values["interface"] != detected_interface:
        values.update({"ipv4_cidr": "", "ipv4_gateway": "", "ipv6_cidr": None, "ipv6_gateway": None})
    print(f"User timezone target: {account.pw_name} ({account.pw_dir})")
    values["ipv4_cidr"] = str(ask("IPv4/CIDR", values["ipv4_cidr"], lambda v: parse_cidr(v, 4, "ipv4_cidr")))
    values["ipv4_gateway"] = str(ask("IPv4 gateway", values["ipv4_gateway"], lambda v: parse_address(v, 4, "ipv4_gateway")))
    values["ipv6_enabled"] = ask_yes_no("Configure static IPv6?", False)
    if values["ipv6_enabled"]:
        values["ipv6_cidr"] = str(ask("IPv6/CIDR", values["ipv6_cidr"], lambda v: parse_cidr(v, 6, "ipv6_cidr")))
        values["ipv6_gateway"] = str(ask("IPv6 gateway", values["ipv6_gateway"], lambda v: parse_address(v, 6, "ipv6_gateway")))
    else:
        values.update({"ipv6_cidr": None, "ipv6_gateway": None})
    values["user_timezone"] = ask("User timezone", values["user_timezone"], validate_timezone)
    values["motd"] = ask_yes_no("Install RzandAl Debian Server Info MOTD?", True)
    return Profile.from_dict(values, current_user=account.pw_name)


def format_plan(plan: dict[str, Any]) -> str:
    base = plan["base"]
    lines = ["Base:"]
    for label, key in (
        ("Hostname", "hostname"), ("Interface", "interface"), ("Invoking user", "user"),
        ("IPv4", "ipv4"), ("IPv4 gateway", "ipv4_gateway"), ("IPv6", "ipv6"),
        ("IPv6 gateway", "ipv6_gateway"), ("Locale", "locale"),
        ("System TZ", "system_timezone"), ("User TZ", "user_timezone"),
    ):
        lines.append(f"  {label}: {base[key] if base[key] is not None else 'not configured'}")
    lines.append("  DNS: " + ", ".join(base["dns"]))
    if plan.get("ipv6_probe") is not None:
        targets = plan["ipv6_probe"]["targets"]
        lines.append("  Planned IPv6 check after confirmation: DAD, gateway NDP, candidate-bound TCP to "
                     + ", ".join(f"[{target['address']}]:{target['port']}" for target in targets))
    if base["ipv4_gateway_off_link"]:
        lines.append("  IPv4 routing: gateway is outside the prefix; an explicit gateway route is required")
    if base["ipv6_gateway_off_link"]:
        lines.append("  IPv6 routing: gateway is outside the prefix; provider routing must be verified")
    lines.extend(["", "APT sources:", *(f"  {source}" for source in base["apt_sources"]),
                  "", "Base packages:", "  " + ", ".join(base["packages"]), "", "Modules:",
                  f"  MOTD: {'yes' if plan['modules']['motd']['selected'] else 'no'} ({MOTD_SOURCE_REF})",
                  "  Firewall: planned", "  VPN: planned", "", "Planned managed files:",
                  *(f"  {path}" for path in plan["planned_managed_files"]), "",
                  "Preview only. Apply is not implemented in this development build."])
    return "\n".join(lines)


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    values: dict[str, Any] = {}
    for key, value in pairs:
        if key in values:
            raise ValidationError(f"profile: duplicate JSON key: {key}")
        values[key] = value
    return values


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--config", type=Path, help="validate and preview a JSON profile")
    parser.add_argument("--json", action="store_true", help="emit the plan as JSON (requires --config)")
    parser.add_argument("--inspect", action="store_true", help="run read-only host preflight and show exact file changes")
    parser.add_argument("--diff", action="store_true", help="show unified file diffs (implies --inspect)")
    args = parser.parse_args(argv)
    if args.json and not args.config:
        parser.error("--json requires --config to keep stdout machine-readable")
    try:
        if args.config:
            values = json.loads(args.config.read_text(), object_pairs_hook=reject_duplicate_keys)
            profile = Profile.from_dict(values)
        else:
            if not sys.stdin.isatty():
                raise ValidationError("an interactive terminal or --config is required")
            profile = collect_profile()
        plan = build_plan(profile)
        if args.inspect or args.diff:
            from preflight import prepare_host_plan
            plan["host_plan"] = prepare_host_plan(profile, invoking_account(), plan, merge_profile_timezone)
        if args.json:
            print(json.dumps(plan, indent=2, ensure_ascii=False))
        else:
            print(format_plan(plan))
            if "host_plan" in plan:
                from preflight import format_host_plan
                print(format_host_plan(plan["host_plan"], show_diff=args.diff))
        return 2 if plan.get("host_plan", {}).get("blockers") else 0
    except (ValidationError, OSError, ValueError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 2
    except (EOFError, KeyboardInterrupt):
        print("\nCancelled. No system changes were made.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
