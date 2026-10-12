"""Linux/OpenSSH connection evidence; environment strings are never proof."""

from __future__ import annotations

import ipaddress
import os
from pathlib import Path
import re
import stat
import sys
import time


# recovery.py preloads explicit siblings for the private python -I worker.
bootstrap = sys.modules.get("bootstrap")
transaction = sys.modules.get("transaction")
if bootstrap is None or transaction is None:
    raise RuntimeError("SSH evidence requires the trusted recovery module loader")

SESSION_EXECUTABLE = "/usr/lib/openssh/sshd-session"
MAX_ANCESTORS = 64
MAX_PROC_BYTES = 1024 * 1024


def account_identity() -> dict:
    account = bootstrap.invoking_account()
    return {"name": account.pw_name, "uid": account.pw_uid, "gid": account.pw_gid}


def validate_account(value: dict) -> None:
    if (not isinstance(value, dict) or set(value) != {"name", "uid", "gid"}
            or any(type(value.get(key)) is not int or not 0 <= value[key] < 2**32 - 1 for key in ("uid", "gid"))):
        raise transaction.TransactionError("Invalid SSH acknowledgment account")
    bootstrap.validate_user(value["name"])


def address(value: str) -> str:
    if not isinstance(value, str) or "%" in value or "/" in value:
        raise transaction.TransactionError("Invalid SSH endpoint address")
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError as error:
        raise transaction.TransactionError("Invalid SSH endpoint address") from error
    if parsed.is_unspecified or parsed.is_multicast:
        raise transaction.TransactionError("SSH endpoints must be unicast addresses")
    return str(parsed.ipv4_mapped if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped else parsed)


def connection(value: str) -> dict:
    pieces = value.split() if isinstance(value, str) else []
    if len(pieces) != 4 or any(not re.fullmatch(r"[0-9]{1,5}", pieces[i]) or not 1 <= int(pieces[i]) <= 65535 for i in (1, 3)):
        raise transaction.TransactionError("Invalid SSH_CONNECTION hint")
    return {"client_address": address(pieces[0]), "client_port": int(pieces[1]),
            "server_address": address(pieces[2]), "server_port": int(pieces[3])}


def validate_evidence(value: dict, account: dict) -> None:
    if (not isinstance(value, dict) or set(value) != {"account", "monitor_pid", "monitor_start_ticks", "socket_inode", "connection"}
            or value.get("account") != account
            or any(type(value.get(key)) is not int or value[key] <= 0 for key in ("monitor_pid", "monitor_start_ticks", "socket_inode"))):
        raise transaction.TransactionError("Invalid authenticated SSH evidence")
    endpoint = value["connection"]
    if not isinstance(endpoint, dict) or set(endpoint) != {"client_address", "client_port", "server_address", "server_port"}:
        raise transaction.TransactionError("Invalid authenticated SSH connection")
    if any(type(endpoint[key]) is not int for key in ("client_port", "server_port")):
        raise transaction.TransactionError("Invalid SSH port")
    canonical = connection(f"{endpoint['client_address']} {endpoint['client_port']} {endpoint['server_address']} {endpoint['server_port']}")
    if canonical != endpoint:
        raise transaction.TransactionError("Noncanonical SSH connection")


def same_connection(left: dict, right: dict) -> bool:
    return all(left[key] == right[key] for key in ("monitor_pid", "monitor_start_ticks", "socket_inode", "connection"))


def read_text(path: Path, limit: int = MAX_PROC_BYTES) -> str:
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise transaction.TransactionError("Process evidence exceeds its bounded read limit")
    return data.decode("ascii")


def parse_stat(value: str) -> dict:
    # comm may contain spaces and ')' characters; the final ')' ends the name.
    prefix, closing, tail = value.rpartition(")")
    fields = tail.split()
    if not closing or "(" not in prefix or len(fields) < 20:
        raise transaction.TransactionError("Invalid kernel process stat")
    pid = int(prefix.split("(", 1)[0].strip())
    ppid, started = int(fields[1]), int(fields[19])
    if pid <= 0 or ppid < 0 or started <= 0 or fields[0] in {"Z", "X", "x"}:
        raise transaction.TransactionError("Process evidence is no longer live")
    return {"pid": pid, "ppid": ppid, "start_ticks": started}


def tcp_endpoint(value: str, family: int) -> tuple[str, int]:
    raw, port = value.split(":")
    expected = 8 if family == 4 else 32
    if len(raw) != expected or not re.fullmatch(r"[0-9A-Fa-f]+", raw) or not re.fullmatch(r"[0-9A-Fa-f]{4}", port):
        raise transaction.TransactionError("Invalid kernel TCP endpoint")
    # /proc TCP stores each 32-bit word in host byte order, including IPv6.
    packed = b"".join(int(raw[index:index + 8], 16).to_bytes(4, sys.byteorder) for index in range(0, expected, 8))
    return address(str(ipaddress.ip_address(packed))), int(port, 16)


class ProcReader:
    def process(self, pid: int) -> dict:
        directory = Path("/proc") / str(pid)
        first = parse_stat(read_text(directory / "stat", 4096))
        fields = dict(line.split(":", 1) for line in read_text(directory / "status", 16384).splitlines() if ":" in line)
        uids, gids = [int(item) for item in fields["Uid"].split()], [int(item) for item in fields["Gid"].split()]
        if len(uids) != 4 or len(gids) != 4 or first["pid"] != pid:
            raise transaction.TransactionError("Invalid process credentials")
        executable = os.readlink(directory / "exe")
        result = {**first, "uids": uids, "gids": gids, "exe": executable}
        if parse_stat(read_text(directory / "stat", 4096)) != first:
            raise transaction.TransactionError("Process changed while collecting SSH evidence")
        return result

    def trusted_session(self, process: dict) -> bool:
        if process["exe"] != SESSION_EXECUTABLE:
            return False
        executable = Path(SESSION_EXECUTABLE)
        for path in (executable, *executable.parents):
            value = path.lstat()
            expected_type = stat.S_ISREG if path == executable else stat.S_ISDIR
            if value.st_uid != 0 or value.st_mode & 0o022 or not expected_type(value.st_mode):
                raise transaction.TransactionError("OpenSSH executable path is not root-owned and protected")
        running = Path("/proc") / str(process["pid"]) / "exe"
        if not os.path.samefile(running, executable):
            raise transaction.TransactionError("Running SSH executable differs from the protected system binary")
        return True

    def transport(self, pid: int) -> tuple[int, dict]:
        directory = Path("/proc") / str(pid)
        inodes = set()
        descriptors = list((directory / "fd").iterdir())
        if len(descriptors) > 4096:
            raise transaction.TransactionError("Too many SSH monitor descriptors")
        for descriptor in descriptors:
            target = os.readlink(descriptor)
            match = re.fullmatch(r"socket:\[([0-9]+)\]", target)
            if match:
                inodes.add(int(match[1]))
        matches = {}
        for family, name in ((4, "tcp"), (6, "tcp6")):
            for line in read_text(directory / "net" / name).splitlines()[1:]:
                fields = line.split()
                if len(fields) < 10:
                    raise transaction.TransactionError("Invalid kernel TCP inventory")
                inode = int(fields[9])
                if inode not in inodes or fields[3] != "01":
                    continue
                local, local_port = tcp_endpoint(fields[1], family)
                remote, remote_port = tcp_endpoint(fields[2], family)
                matches[inode] = {"client_address": remote, "client_port": remote_port,
                                  "server_address": local, "server_port": local_port}
        if len(matches) != 1:
            raise transaction.TransactionError("Cannot establish a unique live SSH monitor TCP connection")
        return next(iter(matches.items()))


class SSHInspector:
    def __init__(self, reader: ProcReader | None = None):
        self.reader = reader or ProcReader()

    @staticmethod
    def account() -> dict:
        return account_identity()

    @staticmethod
    def ticks() -> int:
        return time.clock_gettime_ns(time.CLOCK_BOOTTIME) * os.sysconf("SC_CLK_TCK") // 1_000_000_000

    def capture(self, account: dict, *, required: bool = True) -> dict | None:
        validate_account(account)
        chain, visited = [], set()
        pid = os.getpid()
        while pid > 1:
            if pid in visited or len(chain) >= MAX_ANCESTORS:
                raise transaction.TransactionError("Process ancestry is cyclic or too deep")
            visited.add(pid)
            process = self.reader.process(pid)
            chain.append(process)
            pid = process["ppid"]
        sessions = [process for process in chain if self.reader.trusted_session(process)]
        if not sessions:
            if required or "SSH_CONNECTION" in os.environ:
                raise transaction.TransactionError("Acknowledgment requires an authenticated direct SSH session")
            return None  # A console may launch the future transaction.
        authenticated, monitor = sessions[0], sessions[-1]
        if (authenticated["pid"] == monitor["pid"] or monitor["uids"] != [0] * 4
                or authenticated["uids"] != [account["uid"]] * 4
                or authenticated["gids"] != [account["gid"]] * 4):
            raise transaction.TransactionError("SSH authenticated account differs from the invoking account")
        inode, endpoint = self.reader.transport(monitor["pid"])
        # Rewalk every captured parent link and credential after the socket read.
        if any(self.reader.process(process["pid"]) != process for process in chain):
            raise transaction.TransactionError("SSH ancestry changed during evidence collection")
        if "SSH_CONNECTION" in os.environ and connection(os.environ["SSH_CONNECTION"]) != endpoint:
            raise transaction.TransactionError("SSH_CONNECTION hint differs from the kernel connection")
        evidence = {"account": account, "monitor_pid": monitor["pid"],
                    "monitor_start_ticks": monitor["start_ticks"], "socket_inode": inode, "connection": endpoint}
        validate_evidence(evidence, account)
        return evidence
