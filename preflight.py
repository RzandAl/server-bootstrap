"""Read-only host audit and exact, in-memory file candidates.

This module never writes target files, executes hooks, installs packages, sends
probe traffic, or changes live networking. Unsupported migrations block staging.
"""

from __future__ import annotations

from dataclasses import dataclass
import difflib
import glob
import hashlib
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import shutil
import stat
import subprocess
from typing import Any, Callable
from urllib.parse import urlsplit


NETWORK_BEGIN = "# >>> RzandAl Server Bootstrap network >>>"
NETWORK_END = "# <<< RzandAl Server Bootstrap network <<<"
APT_BEGIN = "# >>> RzandAl Server Bootstrap APT >>>"
APT_END = "# <<< RzandAl Server Bootstrap APT <<<"
MAX_FILE_BYTES = 1024 * 1024
SYSTEM_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
REQUIRED_TOOLS = ("ip", "ifquery", "ifup", "ifdown", "systemctl", "locale",
                  "dpkg-query", "apt-get", "hostnamectl", "timedatectl")
TOP_LEVEL = {"iface", "auto", "allow-auto", "allow-hotplug", "source", "source-directory",
             "mapping", "rename", "no-auto-down", "no-scripts"}


class AuditError(ValueError):
    """The inspected state cannot be staged without guessing or discarding it."""


@dataclass(frozen=True)
class FileState:
    path: str
    kind: str
    data: bytes = b""
    target: str | None = None
    mode: int | None = None
    uid: int | None = None
    gid: int | None = None
    inode: int | None = None
    device: int | None = None
    mtime_ns: int | None = None

    def text(self) -> str:
        if self.kind not in {"regular", "absent"}:
            raise AuditError(f"{self.path}: expected a regular file, found {self.kind}")
        try:
            result = self.data.decode("utf-8")
        except UnicodeDecodeError as error:
            raise AuditError(f"{self.path}: text is not UTF-8") from error
        if "\0" in result:
            raise AuditError(f"{self.path}: NUL bytes in a text configuration")
        return result

    def fingerprint(self) -> dict[str, Any]:
        return {"kind": self.kind, "sha256": hashlib.sha256(self.data).hexdigest()
                if self.kind == "regular" else None, "target": self.target,
                "mode": self.mode, "uid": self.uid, "gid": self.gid,
                "inode": self.inode, "device": self.device, "mtime_ns": self.mtime_ns}


class SystemView:
    """Bounded reads. The alternate root exists for fixtures, not as a CLI option."""

    def __init__(self, root: Path = Path("/")):
        self.root = root
        self.files: dict[str, FileState] = {}
        self.patterns: dict[str, list[str]] = {}

    def local(self, path: str) -> Path:
        if not path.startswith("/") or ".." in PurePosixPath(path).parts:
            raise AuditError(f"{path}: unsafe configuration path")
        return self.root / path.lstrip("/")

    def file(self, path: str) -> FileState:
        if path in self.files:
            return self.files[path]
        local = self.local(path)
        # A final symlink can be planned explicitly; intermediate symlinks cannot.
        for parent in reversed(local.parents):
            if parent == self.root or self.root not in parent.parents:
                continue
            if parent.is_symlink():
                raise AuditError(f"{path}: parent directory is a symlink: {parent}")
        try:
            info = local.lstat()
        except FileNotFoundError:
            result = FileState(path, "absent")
        else:
            metadata = dict(mode=stat.S_IMODE(info.st_mode), uid=info.st_uid, gid=info.st_gid,
                            inode=info.st_ino, device=info.st_dev, mtime_ns=info.st_mtime_ns)
            if stat.S_ISLNK(info.st_mode):
                if os.listxattr(local, follow_symlinks=False):
                    raise AuditError(f"{path}: symlink extended attributes require review")
                result = FileState(path, "symlink", target=os.readlink(local), **metadata)
            elif stat.S_ISREG(info.st_mode):
                if info.st_size > MAX_FILE_BYTES or info.st_nlink != 1:
                    raise AuditError(f"{path}: oversized or hard-linked file requires review")
                # Do not follow a symlink swapped in after lstat; compare the descriptor.
                descriptor = os.open(local, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                with os.fdopen(descriptor, "rb") as stream:
                    opened = os.fstat(stream.fileno())
                    if (opened.st_dev, opened.st_ino, opened.st_mode, opened.st_size,
                            opened.st_mtime_ns) != (info.st_dev, info.st_ino, info.st_mode,
                                                   info.st_size, info.st_mtime_ns):
                        raise AuditError(f"{path}: changed while being inspected")
                    if os.listxattr(stream.fileno()):
                        raise AuditError(f"{path}: extended attributes/ACLs require a preservation backend")
                    data = stream.read(MAX_FILE_BYTES + 1)
                    after = os.fstat(stream.fileno())
                    if len(data) > MAX_FILE_BYTES or after.st_mtime_ns != opened.st_mtime_ns:
                        raise AuditError(f"{path}: changed while being inspected")
                result = FileState(path, "regular", data=data, **metadata)
            else:
                raise AuditError(f"{path}: special file requires review")
        self.files[path] = result
        return result

    def paths(self, pattern: str) -> list[str]:
        result = sorted("/" + str(Path(path).relative_to(self.root))
                        for path in glob.glob(str(self.local(pattern))))
        if pattern in self.patterns and self.patterns[pattern] != result:
            raise AuditError(f"{pattern}: directory inventory changed during preflight")
        self.patterns[pattern] = result
        return result

    def exists(self, path: str) -> bool:
        return self.local(path).exists()

    def available(self, command: str) -> bool:
        return shutil.which(command, path=SYSTEM_PATH) is not None

    def query(self, arguments: list[str]) -> tuple[int, str]:
        try:
            executable = shutil.which(arguments[0], path=SYSTEM_PATH)
            if executable is None:
                return 127, ""
            result = subprocess.run([executable, *arguments[1:]], capture_output=True, text=True, timeout=8,
                                    check=False, env={"PATH": SYSTEM_PATH, "LC_ALL": "C"})
            return result.returncode, result.stdout
        except (OSError, subprocess.SubprocessError):
            return 127, ""


def managed_range(text: str, begin: str, end: str) -> tuple[int, int] | None:
    lines = text.splitlines(keepends=True)
    starts = [i for i, line in enumerate(lines) if line.rstrip("\r\n") == begin]
    ends = [i for i, line in enumerate(lines) if line.rstrip("\r\n") == end]
    if not starts and not ends:
        return None
    if len(starts) != 1 or len(ends) != 1 or starts[0] >= ends[0]:
        raise AuditError("Malformed or duplicate RzandAl managed markers")
    return starts[0], ends[0] + 1


def merge_block(original: str, block: str, begin: str, end: str) -> str:
    span = managed_range(original, begin, end)
    if span:
        lines = original.splitlines(keepends=True)
        return "".join(lines[:span[0]]) + block + "".join(lines[span[1]:])
    separator = "" if not original or original.endswith("\n\n") else ("\n" if original.endswith("\n") else "\n\n")
    return original + separator + block


def network_documents(view: SystemView, interface: str) -> tuple[dict[str, str], dict[str, dict[str, str]]]:
    documents: dict[str, str] = {}
    extras: dict[str, dict[str, str]] = {}
    active: set[str] = set()
    seen_families: set[str] = set()

    def visit(path: str) -> None:
        if path in active or path in documents:
            raise AuditError(f"{path}: cyclic or repeated ifupdown include")
        if len(documents) >= 128:
            raise AuditError("Too many ifupdown includes")
        active.add(path)
        text = view.file(path).text()
        documents[path] = text
        managed_range(text, NETWORK_BEGIN, NETWORK_END)
        selected = False
        options: dict[str, str] = {}
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if "#" in stripped or "\\" in stripped:
                raise AuditError(f"{path}: inline comments or continuations need a dedicated parser")
            tokens = stripped.split()
            keyword = tokens[0]
            if keyword in TOP_LEVEL or keyword.startswith("allow-"):
                selected = False
                if keyword in {"mapping", "rename", "no-auto-down", "no-scripts"}:
                    raise AuditError(f"{path}: {keyword} changes interface lifecycle; migration requires review")
                if keyword in {"source", "source-directory"}:
                    if len(tokens) < 2:
                        raise AuditError(f"{path}: empty include")
                    for value in tokens[1:]:
                        if not re.fullmatch(r"[A-Za-z0-9_./*?\[\]-]+", value) or ".." in PurePosixPath(value).parts:
                            raise AuditError(f"{path}: unsupported include expansion")
                        pattern = value if value.startswith("/") else str(PurePosixPath(path).parent / value)
                        if not pattern.startswith("/etc/network/"):
                            raise AuditError(f"{path}: include outside /etc/network requires review")
                        for matched in view.paths(pattern):
                            if keyword == "source-directory":
                                directory = view.local(matched)
                                if directory.is_symlink() or not directory.is_dir():
                                    raise AuditError(f"{matched}: unsafe include directory")
                                for child in view.paths(matched.rstrip("/") + "/*"):
                                    if re.fullmatch(r"[A-Za-z0-9_-]+", PurePosixPath(child).name):
                                        visit(child)
                            else:
                                visit(matched)
                elif keyword == "iface":
                    if len(tokens) != 4:
                        raise AuditError(f"{path}: templates or malformed iface definition require review")
                    name, family, method = tokens[1:]
                    if method in {"dhcp", "auto"}:
                        raise AuditError(f"{path}: DHCP/SLAAC migration and resolver ownership are not implemented")
                    if name == interface:
                        if family not in {"inet", "inet6"} or method not in {"static", "manual"}:
                            raise AuditError(f"{path}: unsupported selected interface method")
                        if family in seen_families:
                            raise AuditError(f"{interface}: multiple {family} stanzas require review")
                        seen_families.add(family)
                        options = extras.setdefault(family, {})
                        selected = True
                elif any(not re.fullmatch(r"[A-Za-z0-9_.-]+", token) for token in tokens[1:]):
                    raise AuditError(f"{path}: interface patterns or logical mappings require review")
            elif selected:
                if len(tokens) != 2 or keyword not in {"address", "netmask", "gateway", "pointopoint", "mtu", "metric", "hwaddress"}:
                    raise AuditError(f"{path}: selected interface option {keyword} requires review")
                if keyword in options:
                    raise AuditError(f"{path}: duplicate selected interface option {keyword}")
                value = tokens[1]
                if keyword in {"mtu", "metric"} and not re.fullmatch(r"[0-9]{1,10}", value):
                    raise AuditError(f"{path}: invalid {keyword}")
                if keyword == "mtu" and not 68 <= int(value) <= 65535:
                    raise AuditError(f"{path}: MTU outside the supported range")
                if keyword == "metric" and int(value) > 4294967295:
                    raise AuditError(f"{path}: metric outside the supported range")
                if keyword == "hwaddress" and not re.fullmatch(r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", value):
                    raise AuditError(f"{path}: invalid hardware address")
                options[keyword] = value
        active.remove(path)

    visit("/etc/network/interfaces")
    return documents, extras


def render_network(documents: dict[str, str], extras: dict[str, dict[str, str]], base: dict[str, Any]) -> dict[str, str]:
    interface = base["interface"]
    ipv4 = ipaddress.ip_interface(base["ipv4"])
    if base["ipv4_gateway_off_link"] and ipv4.network.prefixlen != 32:
        raise AuditError("Off-link IPv4 gateways are staged only for /32; other prefixes require routing design")
    if base["ipv6_gateway_off_link"]:
        raise AuditError("Off-link global IPv6 gateway requires provider-specific routing design")
    for key in ("mtu", "hwaddress"):
        values = {options[key] for options in extras.values() if key in options}
        if len(values) > 1:
            raise AuditError(f"Conflicting interface-wide {key} values require review")
    if base["ipv6_enabled"] and any(int(options["mtu"]) < 1280 for options in extras.values() if "mtu" in options):
        raise AuditError("Selected IPv6 requires MTU of at least 1280")
    block = f"{NETWORK_BEGIN}\nauto {interface}\niface {interface} inet static\n    address {base['ipv4']}\n"
    if base["ipv4_gateway_off_link"]:
        block += f"    pointopoint {base['ipv4_gateway']}\n"
    block += f"    gateway {base['ipv4_gateway']}\n"
    for family in ("inet", "inet6"):
        if family == "inet6":
            if not base["ipv6_enabled"]:
                break
            block += f"\niface {interface} inet6 static\n    address {base['ipv6']}\n    gateway {base['ipv6_gateway']}\n"
        for key in ("mtu", "metric", "hwaddress"):
            if key in extras.get(family, {}):
                block += f"    {key} {extras[family][key]}\n"
    block += NETWORK_END + "\n"
    output = {}
    for path, text in documents.items():
        span = managed_range(text, NETWORK_BEGIN, NETWORK_END)
        if span and path != "/etc/network/interfaces":
            raise AuditError("Managed network block outside /etc/network/interfaces requires review")
        lines = text.splitlines(keepends=True)
        result = []
        selected = False
        for index, line in enumerate(lines):
            if span and span[0] <= index < span[1]:
                result.append(line)
                selected = False
                continue
            tokens = line.strip().split()
            if not tokens or line.lstrip().startswith("#"):
                result.append(line)
                continue
            keyword = tokens[0]
            if keyword in TOP_LEVEL or keyword.startswith("allow-"):
                selected = keyword == "iface" and tokens[1] == interface
                if selected:
                    continue
                if keyword == "auto" or keyword.startswith("allow-"):
                    names = [name for name in tokens[1:] if name != interface]
                    if len(names) != len(tokens[1:]):
                        if names:
                            result.append(f"{keyword} {' '.join(names)}\n")
                        continue
            if not selected:
                result.append(line)
        candidate = "".join(result)
        if path == "/etc/network/interfaces":
            candidate = merge_block(candidate, block, NETWORK_BEGIN, NETWORK_END)
        output[path] = candidate
    return output


def official_uri(uri: str) -> bool:
    parsed = urlsplit(uri)
    return (parsed.scheme in {"http", "https"} and parsed.username is None and parsed.password is None
            and parsed.port is None and not parsed.query and not parsed.fragment
            and (parsed.hostname or "").endswith(".debian.org")
            and parsed.path.rstrip("/") in {"/debian", "/debian-security"})


def installed_packages(output: str) -> set[str]:
    installed = set()
    for line in output.splitlines():
        fields = line.split("\t")
        if len(fields) != 2 or len(fields[1]) != 3:
            raise AuditError("Malformed dpkg package inventory")
        package, status = fields
        if status[2] != " ":
            raise AuditError(f"dpkg reports an error/reinstall-required state: {package}")
        # The first character is the desired selection (including 'h' for hold).
        # The second character describes what is actually installed.
        if status[1] == "i":
            installed.add(package)
    return installed


def render_apt(documents: dict[str, str], sources: list[str]) -> dict[str, str]:
    suites = {"trixie", "trixie-security", "trixie-updates"}
    output = {}
    for path, text in documents.items():
        if path.endswith(".sources"):
            result = []
            for paragraph in re.split(r"(\n[ \t]*\n)", text):
                fields: dict[str, str] = {}
                previous = None
                for line in paragraph.splitlines():
                    if not line.strip() or line.lstrip().startswith("#"):
                        continue
                    if line[0].isspace() and previous:
                        fields[previous] += " " + line.strip()
                    elif ":" in line:
                        key, value = line.split(":", 1)
                        key = key.lower()
                        if not re.fullmatch(r"[a-z][a-z0-9-]*", key) or key in fields:
                            raise AuditError(f"{path}: malformed or duplicate deb822 field")
                        fields[key] = value.strip()
                        previous = key
                    else:
                        raise AuditError(f"{path}: malformed deb822 paragraph")
                if not fields or fields.get("enabled", "yes").lower() == "no":
                    result.append(paragraph)
                    continue
                if fields.get("enabled", "yes").lower() != "yes":
                    raise AuditError(f"{path}: unknown deb822 Enabled value")
                uris = fields.get("uris", "").split()
                if not uris or not fields.get("types") or not fields.get("suites"):
                    raise AuditError(f"{path}: incomplete deb822 source")
                official = [official_uri(uri) for uri in uris]
                if any(official):
                    if not all(official) or not set(fields["suites"].split()) <= suites:
                        raise AuditError(f"{path}: mixed official/third-party sources or nonstandard Debian suites")
                    result.extend(line + "\n" for line in paragraph.splitlines() if line.lstrip().startswith("#"))
                else:
                    result.append(paragraph)
            output[path] = "".join(result)
        else:
            span = managed_range(text, APT_BEGIN, APT_END)
            if span and path != "/etc/apt/sources.list":
                raise AuditError(f"{path}: unexpected managed APT block")
            result = []
            for index, line in enumerate(text.splitlines(keepends=True)):
                if (span and span[0] <= index < span[1]) or not line.strip() or line.lstrip().startswith("#"):
                    result.append(line)
                    continue
                tokens = shlex.split(line, comments=True)
                if not tokens or tokens[0] not in {"deb", "deb-src"}:
                    raise AuditError(f"{path}: unsupported source line")
                position = 1
                if len(tokens) > 1 and tokens[1].startswith("["):
                    while position < len(tokens) and not tokens[position].endswith("]"):
                        position += 1
                    position += 1
                if len(tokens) <= position + 1:
                    raise AuditError(f"{path}: incomplete source line")
                uri, suite = tokens[position:position + 2]
                if official_uri(uri):
                    if suite not in suites:
                        raise AuditError(f"{path}: nonstandard Debian suite {suite}")
                else:
                    result.append(line)
            output[path] = "".join(result)
    canonical = "/etc/apt/sources.list"
    block = APT_BEGIN + "\n" + "\n".join(sources) + "\n" + APT_END + "\n"
    output[canonical] = merge_block(output.get(canonical, ""), block, APT_BEGIN, APT_END)
    return output


def render_hosts(original: str, old_hostname: str, hostname: str) -> str:
    lines = original.splitlines(keepends=True)
    matches = []
    for index, line in enumerate(lines):
        body = line.split("#", 1)[0].split()
        if body and body[0] == "127.0.1.1":
            matches.append((index, body[1:]))
    if len(matches) > 1:
        raise AuditError("/etc/hosts: multiple 127.0.1.1 mappings require review")
    if matches:
        index, names = matches[0]
        if hostname in names and old_hostname == hostname:
            return original
        old_names = {old_hostname, old_hostname.split(".")[0]}
        aliases = [name for name in names if name != hostname and name not in old_names
                   and not (old_hostname and name.startswith(old_hostname.split(".")[0] + "."))]
        comment = " #" + lines[index].split("#", 1)[1].rstrip("\r\n") if "#" in lines[index] else ""
        lines[index] = "127.0.1.1\t" + " ".join([hostname, *aliases]) + comment + "\n"
        return "".join(lines)
    return original + ("" if not original or original.endswith("\n") else "\n") + f"127.0.1.1\t{hostname}\n"


def prepare_host_plan(profile: Any, account: Any, plan: dict[str, Any], timezone_merge: Callable,
                      *, view: SystemView | None = None) -> dict[str, Any]:
    view = view or SystemView()
    blockers: list[str] = []
    warnings: list[str] = []
    facts: dict[str, Any] = {"account": {"name": account.pw_name, "uid": account.pw_uid,
                                       "gid": account.pw_gid, "home": account.pw_dir,
                                       "shell": account.pw_shell}}
    candidates: dict[str, str] = {}
    base = plan["base"]

    def check(operation: Callable) -> Any:
        try:
            return operation()
        except (AuditError, OSError, ValueError) as error:
            blockers.append(str(error))
            return None

    def text(path: str) -> str:
        return view.file(path).text()

    def release() -> None:
        path = "/etc/os-release"
        state = view.file(path)
        if state.kind == "symlink":
            if state.target not in {"../usr/lib/os-release", "/usr/lib/os-release"}:
                raise AuditError("/etc/os-release: unexpected symlink")
            path = "/usr/lib/os-release"
        values = {}
        for line in text(path).splitlines():
            if line.strip() and not line.lstrip().startswith("#"):
                key, separator, raw = line.partition("=")
                if not separator or key in values:
                    raise AuditError("os-release: malformed or duplicate field")
                tokens = shlex.split(raw)
                values[key] = tokens[0] if len(tokens) == 1 else ""
        facts["os"] = {key: values.get(key) for key in ("ID", "VERSION_ID", "VERSION_CODENAME")}
        if values.get("ID") != "debian" or values.get("VERSION_ID") != "13" or values.get("VERSION_CODENAME") != "trixie":
            raise AuditError("Host preflight supports Debian 13 (trixie) only")

    check(release)
    if account.pw_name != profile.user or not account.pw_dir.startswith("/") or ".." in PurePosixPath(account.pw_dir).parts:
        blockers.append("Invoking account or passwd home does not match the plan")
    if not view.exists(account.pw_dir):
        blockers.append("Invoking account's passwd home does not exist")
    if account.pw_shell not in {"/bin/bash", "/usr/bin/bash", "/bin/sh", "/usr/bin/sh", "/bin/dash", "/usr/bin/dash"}:
        blockers.append("Invoking account's shell does not have a supported .profile lifecycle")
    facts["missing_tools"] = [command for command in REQUIRED_TOOLS if not view.available(command)]
    if facts["missing_tools"]:
        blockers.append("Missing preflight/apply prerequisites: " + ", ".join(facts["missing_tools"]))
    code, output = view.query(["locale", "-a"])
    if code or "c.utf8" not in {name.lower().replace("-", "") for name in output.splitlines()}:
        blockers.append("C.UTF-8 is not available or locale inventory failed")
    code, output = view.query(["dpkg-query", "-W", "-f=${Package}\t${db:Status-Abbrev}\n"])
    packages = check(lambda: installed_packages(output)) or set()
    if code:
        blockers.append("Installed package inventory failed")
    facts["missing_base_packages"] = sorted(set(base["packages"]) - packages)
    for package in ("ifupdown", "iproute2", "tzdata", "ca-certificates", "debian-archive-keyring"):
        if package not in packages:
            blockers.append(f"Missing required installed package: {package}")
    if {"resolvconf", "openresolv", "ifupdown2", "dhcpcd", "rdnssd"} & packages:
        blockers.append("Unsupported resolver/network lifecycle package is installed")
    units = {}
    for unit in ("networking.service", "NetworkManager.service", "systemd-networkd.service", "systemd-resolved.service"):
        code, output = view.query(["systemctl", "show", "--property=LoadState", "--property=ActiveState", unit])
        properties = dict(line.split("=", 1) for line in output.splitlines() if "=" in line)
        state = properties.get("ActiveState", "unknown")
        absent = properties.get("LoadState") == "not-found" and state == "inactive"
        units[unit] = "not-installed" if absent else state
        if (code and not absent) or state not in {"active", "inactive", "failed"}:
            blockers.append(f"Cannot establish stable service ownership: {unit}")
        elif unit != "networking.service" and state != "inactive":
            blockers.append(f"Unsupported network/DNS manager state: {unit}={state}")
        elif unit == "networking.service" and state != "active":
            blockers.append("ifupdown networking.service is not active")
    facts["services"] = units
    if "cloud-init" in packages or view.exists("/etc/cloud/cloud.cfg"):
        blockers.append("cloud-init is present; targeted hostname/network migration is not implemented")
    for directory in ("/etc/systemd/network", "/etc/NetworkManager/system-connections"):
        if view.paths(directory + "/*"):
            warnings.append(f"Inactive manager configuration exists: {directory}")

    def network() -> None:
        if not view.exists(f"/sys/class/net/{profile.interface}"):
            raise AuditError(f"Selected interface does not exist: {profile.interface}")
        code, output = view.query(["ip", "-j", "address", "show", "dev", profile.interface])
        addresses = json.loads(output) if not code else None
        if not isinstance(addresses, list) or len(addresses) != 1 or not isinstance(addresses[0], dict) or addresses[0].get("ifname") != profile.interface:
            raise AuditError("Cannot inspect the selected live interface")
        facts["interface"] = addresses[0]
        if addresses[0].get("link_type") != "ether" or addresses[0].get("linkinfo", {}).get("info_kind"):
            raise AuditError("Only a plain Ethernet primary VPS interface is staged")
        for family in ("inet", "inet6"):
            infos = [info for info in addresses[0].get("addr_info", []) if info.get("family") == family and info.get("scope") == "global"]
            if len(infos) > 1:
                raise AuditError(f"Selected interface has multiple global {family} addresses")
            if any(info.get("tentative") or info.get("dadfailed") or set(info.get("flags", [])) & {"tentative", "dadfailed"} for info in infos):
                raise AuditError("Existing global address is tentative or has failed DAD")
        for family in ("-4", "-6"):
            code, output = view.query(["ip", "-j", family, "route", "show", "table", "all"])
            routes = json.loads(output) if not code else None
            if not isinstance(routes, list) or not all(isinstance(route, dict) for route in routes):
                raise AuditError(f"Cannot inspect {family} route inventory")
            facts[f"routes{family}"] = routes
            code, output = view.query(["ip", "-j", family, "rule", "show"])
            rules = json.loads(output) if not code else None
            if not isinstance(rules, list) or not all(isinstance(rule, dict) for rule in rules):
                raise AuditError(f"Cannot inspect {family} policy rules")
            facts[f"rules{family}"] = rules
            if any(rule.get("table") not in {"local", "main", "default", 253, 254, 255} for rule in rules):
                raise AuditError("Custom policy routing requires an explicit migration design")
        connection = os.environ.get("SSH_CONNECTION", "").split()
        if connection:
            if len(connection) != 4:
                raise AuditError("Malformed SSH_CONNECTION; cannot establish the current session route")
            peer = str(ipaddress.ip_address(connection[0]))
            local_address = str(ipaddress.ip_address(connection[2]))
            code, output = view.query(["ip", "-j", "route", "get", peer])
            route = json.loads(output) if not code else None
            if not isinstance(route, list) or len(route) != 1 or route[0].get("dev") != profile.interface:
                raise AuditError("Selected primary interface does not carry the current SSH client route")
            facts["ssh"] = {"peer": peer, "local": local_address, "route": route[0]}
        else:
            warnings.append("No SSH_CONNECTION: planning from a local/console session")
        documents, extras = network_documents(view, profile.interface)
        candidates.update(render_network(documents, extras, base))
        warnings.append("Network candidates have not been applied; /32 routing and connectivity still require namespace/VPS validation")

    check(network)
    def apt() -> None:
        for path in ["/etc/apt/apt.conf", *view.paths("/etc/apt/apt.conf.d/*")]:
            if re.search(r"Dir\s*::\s*Etc|#include", text(path)):
                raise AuditError(f"{path}: custom APT source paths/includes require review")
        documents = {"/etc/apt/sources.list": text("/etc/apt/sources.list")}
        for path in view.paths("/etc/apt/sources.list.d/*"):
            if re.fullmatch(r"[A-Za-z0-9_.-]+\.(?:list|sources)", PurePosixPath(path).name):
                documents[path] = text(path)
        candidates.update(render_apt(documents, base["apt_sources"]))
    check(apt)

    def account_files() -> None:
        path = str(PurePosixPath(account.pw_dir) / ".profile")
        original = text(path)
        span = managed_range(original, "# >>> RzandAl Server Bootstrap >>>", "# <<< RzandAl Server Bootstrap <<<")
        lines = original.splitlines(keepends=True)
        outside = "".join(line for index, line in enumerate(lines) if not span or not span[0] <= index < span[1])
        paths = {path: outside, "/etc/environment": text("/etc/environment"), "/etc/profile": text("/etc/profile"),
                 str(PurePosixPath(account.pw_dir) / ".bashrc"): text(str(PurePosixPath(account.pw_dir) / ".bashrc"))}
        for item in view.paths("/etc/profile.d/*.sh"):
            paths[item] = text(item)
        for item, content in paths.items():
            for line in content.splitlines():
                if not line.lstrip().startswith("#") and re.search(r"\b(?:TZ|LANG|LANGUAGE|LC_[A-Z_]+)\s*=", line):
                    raise AuditError(f"{item}: unmanaged timezone/locale assignment requires review")
        if account.pw_shell.endswith("bash"):
            for name in (".bash_profile", ".bash_login"):
                state = view.file(str(PurePosixPath(account.pw_dir) / name))
                if state.kind != "absent":
                    raise AuditError(f"{state.path}: Bash may bypass .profile; explicit startup-file review required")
        candidates[path] = timezone_merge(original, profile.user_timezone)
        facts["profile_path"] = path
    check(account_files)

    def system_files() -> None:
        old_hostname = text("/etc/hostname").strip()
        if old_hostname and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}", old_hostname):
            raise AuditError("/etc/hostname: unexpected existing hostname format")
        resolver = text("/etc/resolv.conf")
        owner_comments = resolver.splitlines()
        if owner_comments and owner_comments[0] == "# Managed by RzandAl Server Bootstrap":
            owner_comments = owner_comments[1:]
        if re.search(r"generated|managed by|do not edit", "\n".join(owner_comments), re.IGNORECASE):
            raise AuditError("/etc/resolv.conf: generated-file ownership requires review")
        # Read all replaced regular files, including locale and timezone, for fingerprints.
        text("/etc/default/locale")
        text("/etc/timezone")
        candidates.update({"/etc/hostname": profile.hostname + "\n",
                           "/etc/hosts": render_hosts(text("/etc/hosts"), old_hostname, profile.hostname),
                           "/etc/resolv.conf": "# Managed by RzandAl Server Bootstrap\n" + "".join(f"nameserver {dns}\n" for dns in base["dns"]),
                           "/etc/default/locale": 'LANG="C.UTF-8"\n', "/etc/timezone": "UTC\n"})
        state = view.file("/etc/localtime")
        if state.kind not in {"regular", "symlink", "absent"} or not view.exists("/usr/share/zoneinfo/UTC"):
            raise AuditError("UTC zoneinfo or /etc/localtime is unavailable")
    check(system_files)

    changes = []
    def change(path: str, content: str) -> None:
        before = view.file(path)
        before.text()
        user_file = path == facts.get("profile_path")
        uid, gid = (account.pw_uid, account.pw_gid) if user_file else (0, 0)
        if before.kind == "regular" and before.uid != uid:
            raise AuditError(f"{path}: unexpected owner requires review")
        mode = before.mode if before.kind == "regular" else 0o644
        after = {"kind": "regular", "content": content, "sha256": hashlib.sha256(content.encode()).hexdigest(),
                 "mode": mode, "uid": uid, "gid": gid}
        changed = before.kind != "regular" or before.data != content.encode() or (before.mode, before.uid, before.gid) != (mode, uid, gid)
        raw_diff = difflib.unified_diff(before.text().splitlines(keepends=True), content.splitlines(keepends=True),
                                       fromfile=path + " (current)", tofile=path + " (candidate)")
        diff = "".join(line if line.endswith("\n") else line + "\n\\ No newline at end of file\n" for line in raw_diff)
        changes.append({"path": path, "changed": changed, "before": before.fingerprint(), "after": after, "diff": diff})
    if not blockers:
        for path, content in sorted(candidates.items()):
            check(lambda path=path, content=content: change(path, content))
        before = view.file("/etc/localtime")
        target = "/usr/share/zoneinfo/UTC"
        changes.append({"path": before.path, "changed": before.kind != "symlink" or before.target != target or before.uid != 0 or before.gid != 0,
                        "before": before.fingerprint(), "after": {"kind": "symlink", "target": target, "uid": 0, "gid": 0},
                        "diff": f"/etc/localtime: {before.kind} {before.target or ''} -> symlink {target}\n"})
    if blockers:
        changes = []
    return {"mode": "read-only-preflight", "apply_available": False, "file_plan_available": not blockers,
            "connectivity_validated": False, "facts": facts, "blockers": list(dict.fromkeys(blockers)),
            "ipv6_probe": plan.get("ipv6_probe"),
            "warnings": warnings, "files": changes,
            "watched_files": {path: state.fingerprint() for path, state in sorted(view.files.items())},
            "watched_patterns": dict(sorted(view.patterns.items())),
            "package_operations": [list(plan["package_commands"]["update"]),
                                   [*plan["package_commands"]["install"], *facts["missing_base_packages"]]]
            if facts["missing_base_packages"] else [list(plan["package_commands"]["update"])]}


def format_host_plan(report: dict[str, Any], *, show_diff: bool = False) -> str:
    lines = ["\nHost preflight:", f"  File plan: {'available' if report['file_plan_available'] else 'blocked'}",
             "  Connectivity: not probed; apply remains unavailable"]
    for message in report["blockers"]:
        lines.append("  Blocker: " + message)
    for message in report["warnings"]:
        lines.append("  Note: " + message)
    lines.append("\nExact file candidates:")
    for item in report["files"]:
        lines.append(f"  {'change' if item['changed'] else 'unchanged'}: {item['path']}")
        after = item["after"]
        metadata = f"{after['kind']}, owner {after['uid']}:{after['gid']}"
        if after["kind"] == "regular":
            metadata += f", mode {after['mode']:04o}"
        else:
            metadata += f", target {after['target']}"
        lines.append("    " + metadata)
        if show_diff and item["changed"]:
            lines.append(item["diff"].rstrip("\n"))
    lines.append("\nPlanned package operations (not executed):")
    lines.extend("  " + shlex.join(operation) for operation in report["package_operations"])
    return "\n".join(lines)
