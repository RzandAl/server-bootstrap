# Independent recovery

`0.4.0-dev` added an internal recovery supervisor and static network journal;
`0.5.0-dev` adds verified fresh SSH acknowledgment for isolated fixtures.
The bootstrap wizard remains read-only. Production Base application and
module/probe wiring are still disabled; there is no bootstrap
`--apply` option or recovery CLI flag that enables them.

## Independent supervisor

The supervisor requires root, a running system systemd manager, its private
socket, and the system D-Bus socket. Read-only planning installs no dependencies.
`arm()` checks prerequisites, the active prepared run, its reviewed file plan,
watched files/inventories, and the initial live network before it permits writes.

| Component | Role |
| --- | --- |
| `runs/<id>/worker/` | Private copied Python recovery bundle, independent of checkout and SSH |
| `supervisor.json` | Checked run/root/unit definitions, bundle hashes, boot generation, deadlines, and phase |
| `network.json` | Initial interface/address/route state, owned operations, durable intent, and recovery outcomes |
| `*-apply.service` | Detached writer; production system root is explicitly rejected |
| `*-rollback.service` | Stops the owned writer and restores both participants; retries failed recovery |
| `*-rollback.timer` | Monotonic timeout plus UTC calendar deadline and persistent missed-event handling |
| `*-boot.service` | Restores original files before sysinit/network startup after manager restart |

Names contain the validated run ID. Existing unit names are never overwritten.
The worker bundle is root-owned/private, invoked with isolated Python mode,
and verified before writing. Profiles never supply shell commands, executable
names, unit names, or quoting/systemd expansion characters.

The timer must be active before the writer starts. Failure invokes independent
rollback; an expired deadline stops the writer's entire service cgroup before
acquiring the shared transaction lock. Only this run's writer is stopped.
Recovery does not kill the user's SSH process or arbitrary PIDs.

Files and network are attempted even if one participant reports a conflict.
The active pointer is cleared only when both succeed. A bare file recovery or
commit cannot finalize a supervised run. Failure keeps private recovery data,
records the incomplete outcome, and blocks another run.

Cleanup shares the same project lock. Terminal state is durable before timer
disarming; a late timer cannot undo a committed run or clear a newer active run.
Unit files are removed only when their content/type/owner/mode still match ours.
An external unit edit is preserved for review.

## Static network subset

The backend uses typed argument arrays to `ip`, never shell evaluation, flushes,
blind route replacement, or a restart of networking. It supports UP Ethernet
interfaces, static global IPv4/IPv6 addresses with permanent lifetimes, IPv4
`/32` peers, and simple unicast main-table routes. Link-local IPv6 gateways are
accepted with an explicit interface. Gateway/external reachability is a separate
probe contract; valid route syntax and successful DAD do not establish it.

Dynamic/finite-lifetime addresses, unsupported address flags/aliases, RA routes,
multipath, unknown route attributes, policy routing, and link/MTU/MAC migration
are outside this backend. Kernel-generated connected routes are not explicitly
mutated; the address lifecycle owns them. Preflight must establish the supported
host subset before production wiring is added.

Deleting the last IPv4 can also remove manual interface routes. Before our
address deletion, durably record exact original routes still present; afterward
record whether they survived. Rollback restores only those implicit losses (or
an unresolved crash intent), with gateway routes before routes that depend on
them. A route already absent before our deletion is never claimed as ours.

Before each mutation, record intent durably and recheck the exact expected
object. An identical preexisting address/route is reused without ownership.
Rollback removes candidate addresses first, restores removed originals next,
then restores manual routes, avoiding IPv4 primary/secondary deletion effects.
IPv6 restoration waits for bounded DAD and rejects failure. Verify the entire
original selected-interface inventory before reporting recovery success.

Unrelated added objects remain. A third version at a managed identity is
preserved and requires manual review. Interface index, MAC, and MTU must still
match, so an unrelated replacement interface is never touched. These guards
detect observed external changes; the project lock does not lock other tools.

## Restart and acknowledgment

Boot recovery uses the changed manager generation and restores original files
before network services start. It does not replay obsolete interface indices or
an old kernel journal into a new boot. The original configuration must then be
loaded by the existing network manager. During early boot, cleanup uses the
manager's private socket; its harmless persistent timer stamp is retained
because the system bus is not yet started. The disabled/removed unit cannot
schedule another run from that stamp.

The commit APIs remain limited to fixture roots. A run armed with an SSH contract
requires a verified new authenticated transport tied to the invoking account and
candidate address. Its final files, preserved/reused static network objects,
guard, and deadlines must still be healthy immediately before terminal commit.
The older fixture callback cannot bypass an SSH contract.
[Fresh SSH acknowledgment](SSH_ACKNOWLEDGMENT.md) covers the evidence and failure
cases. Real Base still needs module health and the temporary IPv6 gateway/external
probe connected to this lifecycle. There is no unattended production commit.

## Console recovery

For an existing supervised run, from a trusted checkout:

```sh
sudo python3 -I recovery.py status <run-id>
sudo python3 -I recovery.py recover <run-id>
```

The installed private worker exposes `_apply` and `_boot` only for its generated
units; these operations reject execution from a normal checkout. There is no
CLI arm/start, arbitrary backup path, or namespace/root override. The `acknowledge`
operation accepts only an existing configured fixture run; the production system
root remains gated.

## Verified scope

Regular Debian CI runs parser/host/file/supervisor regressions as root and an
ordinary user, including real `ifquery` and `systemd-analyze verify`.
A separate disposable Debian 13 container runs systemd as PID 1 and uses private
cgroup and network namespaces. The source checkout is mounted read-only; only
fixture targets, private state, and owned container units are modified.

Integration scenarios exercise static IPv4/IPv6 transitions, `/24` addresses,
`/32` peers, link-local IPv6 gateway routes, automatic deadline recovery after
client exit, a real worker `SIGKILL` during DAD, fixture commit/timer disarming,
and an unresolved-run container restart. They verify actual addresses/routes
and restored original file bytes rather than only command mocks.

Additional namespace scenarios exercise real OpenSSH IPv4/IPv6 reconnection,
sudo caller identity without an environment hint, ControlMaster refusal, and
automatic rollback without a valid acknowledgment.

This does not establish real VPS/provider reachability, the full ifupdown
transition, package failure recovery, or a healthy VPS reboot.
Those remain release acceptance checks, not claims derived from fixture success.
