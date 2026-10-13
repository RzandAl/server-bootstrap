# Fresh SSH acknowledgment

`0.5.0-dev` verifies an authenticated new OpenSSH connection before a supervised
fixture run can commit. The original invoking account is fixed during arming.
`0.6.0-dev` also requires a selected [IPv6 probe](IPV6_PROBE.md) to have passed
and cleaned its temporary objects. `0.7.0-dev` adds complete Base health and
defers old-address removal until acknowledgment. Production Base application remains disabled
until module health and host transitions are connected; this document does not
provide a VPS installer command.

## Connection evidence

`ssh_session.py` reads bounded kernel process and TCP information as root.
It walks the current process's parent chain and identifies Debian 13's protected
`/usr/lib/openssh/sshd-session` executable. The executable and its parent
directories must be root-owned, unwritable by group/others, and match the running
process's executable inode. A process name alone is never sufficient.

The authenticated child must have the original account's real/effective/saved/
filesystem UID and primary GID. Its per-connection privileged monitor must have
root credentials. The monitor must own exactly one established TCP transport;
socket inode and local/remote endpoints come from the kernel. Parent links,
credentials, executable paths, and process start times are reread after the
socket inventory, so an observed exit, replacement, or PID reuse rejects proof.

`SSH_CONNECTION`, when present, must agree with the kernel endpoint. It is an
optional consistency hint. A valid-looking value without SSH ancestry is
rejected. Sudo may remove it; proof still works from the authenticated ancestry
and monitor socket. Consistent sudo metadata must still resolve the original
caller through passwd. Direct root execution remains bound to root.

Detached shells, tmux/screen processes reparented away from SSH, alternate SSH
implementations, modified OpenSSH executables, ambiguous monitor sockets, and
unreadable process information cannot acknowledge a run. Use a direct fresh
OpenSSH session with the invoking account instead. A console can launch a run
but cannot supply reconnection proof.

## Freshness and candidate path

After both file and network application finish, save a private waiting marker
and the current boot-relative clock tick. The privileged monitor's start tick
must be strictly later. A connection opened during application, an original
session, or a new channel on an old ControlMaster transport is rejected.
PID/start-time/socket/endpoint identity also binds the initial SSH connection
when one was present at arming. A connection created in the same clock tick as
completion is inconclusive and requires a later reconnect.

The kernel server endpoint must equal one of the planned final candidate
addresses. A fresh login to an old surviving address cannot validate the desired
path. IPv4-mapped IPv6 socket endpoints are canonicalized to IPv4. IPv6 target
addresses are fully parsed; scoped/link-local target input is not accepted.
The fixture API verifies that these targets exist in its projected final
address inventory. Profiles cannot supply evidence or executable commands.

The reviewed Base fixture profile supplies candidate targets and the invoking
account. Provider reachability remains a VPS acceptance
requirement even with the internal IPv6 probe. SSH proof for one selected
family does not validate the other family's Internet path.

## Commit and failure behavior

Under the shared transaction lock, acknowledgment requires the active applied
run, an intact private worker bundle, matching manager generation, an active
independent timer, and unexpired monotonic and wall-clock deadlines.

Verify candidate file bytes/type/owner/mode, intended static network state, and
the completed/cleaned IPv6 probe when one was armed.
Preserved addresses and reused routes, including an unchanged gateway route,
must remain as reviewed. Kernel connected routes follow address lifecycles;
unrelated additional objects remain allowed.

Persist the proposed connection evidence with an `acknowledging` intent. This
intent is not terminal success. After file verification, recheck networking,
the live SSH connection, and deadlines immediately before durable terminal
commit. Only committed state permits timer/unit cleanup. A rejected proof,
failed health check, closed connection, expired deadline, or incomplete write
leaves independent recovery armed. Rollback retains the original account and
any attempted evidence for diagnosis in private root-owned state.

A crash before terminal commit permits rollback. A crash or cleanup failure
after durable commit preserves the candidate state; late recovery finishes
cleanup without undoing it. Repeating acknowledgment for an already committed
run is idempotent. Existing `0.4.0-dev` and `0.5.0-dev` private bundle manifests remain readable
for recovery from a trusted checkout.

## Existing fixture acknowledgment

For an already applied fixture run armed with this contract, from a new direct
SSH connection to its candidate address under the original invoking account:

```sh
sudo python3 -I recovery.py acknowledge <run-id>
```

There is no token to paste, account selector, arbitrary command callback, or
force flag. The run ID selects private recovery state and is not an SSH proof.
For root login, omit sudo. Use a genuinely new TCP connection, disabling client
multiplexing when needed. Acknowledgment completes the already authorized
transaction; it adds no second Apply prompt or module changes.

## Verification

Regular regressions cover synthetic evidence, corrupted inputs, account/path
mismatches, file/network health, clock boundaries, transport loss, commit races,
private proof durability, legacy recovery, and production-root rejection.

The disposable Debian 13 systemd job runs native OpenSSH between owned client
and server network namespaces. Test keys/accounts and narrowly scoped sudo
rules exist only inside that disposable container; no host ports are published.
The client verifies its generated server host key. Scenarios include IPv4 and
IPv6 login, actual sudo identity without `SSH_CONNECTION`, old ControlMaster
transport refusal, old address/wrong account/forged hint rejection, and automatic
rollback without a valid acknowledgment. Multiplex tests disable TCP fallback
so an unexpected new login cannot falsely satisfy the refusal scenario.

Relevant primary documentation:

- [Debian 13 OpenSSH server](https://manpages.debian.org/trixie/openssh-server/sshd.8.en.html)
- [Linux process stat and start time](https://manpages.debian.org/trixie/manpages/proc_pid_stat.5.en.html)
- [OpenSSH per-session binary design](https://www.openssh.org/releasenotes.html)
