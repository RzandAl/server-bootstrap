# Roadmap

## Foundation — current development build

- [x] Shared README structure, explicit compatibility, MIT, and joint authorship.
- [x] Central defaults and one MOTD source-ref constant.
- [x] Typed profile with strict full-address validation and canonical IP output.
- [x] Read-only interactive collection and text/JSON plan.
- [x] SSH-route/default-route interface discovery without ambiguous address guesses.
- [x] Invoking-account policy, including consistent sudo identity and passwd home.
- [x] Read-only host audit and exact file candidates/diffs for the supported static ifupdown subset.
- [x] APT normalization across legacy/deb822 input with third-party preservation.
- [x] File and include-inventory fingerprints for future stale-plan checks.
- [x] Pure managed `.profile` timezone renderer with repeated-run checks.
- [x] Automated tests and a Debian 13 CI workflow.

This build deliberately has no apply option and is not a production release.

## 1. Host preflight and staged file plan — implemented for the supported subset

The audit inspects Debian 13, invoking account/home, C.UTF-8, prerequisites,
services, cloud-init presence, resolver ownership, live addresses/routes/rules,
ifupdown includes, APT sources, and startup-file conflicts. Unsupported
migrations block the entire file plan. Canonical APT output is the minimal
legacy list; `/32` network candidates use `pointopoint` and `gateway`.

Fixture tests verify preservation and repeatability; Debian CI additionally
uses the real ifupdown parser. Kernel/provider routing and the full effect of
global hooks/environment sources still need validation before apply.
Collection and file preparation are complete for this subset. The one final
confirmation becomes effective only when the transaction engine exists.

**Acceptance:** collect and stage without target changes; reject unsupported
ownership; preserve unrelated fragments; show exact file changes, package
operations, resolver and cloud-init ownership changes, and the single final
confirmation. A cancelled run leaves target bytes and live networking intact.

## 2. Transaction and network recovery

- [x] Single-run file lock and private state, with durable unique run IDs.
- [x] Full changed-file backups: bytes/type, symlink target, owner, mode, mtime,
  and original absence.
- [x] Re-audit the complete reviewed plan, including live facts, then recheck
  watched file fingerprints and include inventories before writing.
- [x] Atomic file replacement with durable write intent, conflict-aware recovery,
  and explicit rejection of unsupported extended attributes/ACLs.
- [x] File recovery by a separate process after writer death, a console command,
  and tests of corruption, concurrent/stale runs, and repeated recovery.
- [x] Protected detached fixture worker, independent persistent/monotonic rollback
  timer, and early-boot file recovery under systemd.
- [x] Restore owned static addresses/main routes, preserve reused objects, and
  verify actual IPv4/IPv6 kernel behavior in isolated namespaces.
- [ ] Connect production Base to the supervisor after host/probe contracts are ready.
- [ ] New-session acknowledgment, health checks, and timer disarming.

The file layer arrived in `0.3.0-dev`; `0.4.0-dev` adds the independent supervisor
and owned network journal. [Independent recovery](RECOVERY.md) describes the
Debian/systemd namespace scenarios, manager-restart test, explicit fixture-only
writer/commit gate, and remaining provider/VPS validation. Production Bootstrap
apply stays unavailable until its acknowledgment and probe guarantees exist.

**Acceptance:** a timeout, lost SSH session, failed step, signal, or stale run
restores both original files and live network state. Reused addresses/routes
are preserved. A confirmed healthy transition survives reboot.

## 3. Base application and IPv6 probe

Implement hostname plus hosts, selected ifupdown stanzas, static DNS, system
locale and timezone, managed user timezone, normalized APT sources, package
index refresh, and missing-package installation.

Add the temporary IPv6 probe after confirmation: DAD, explicit candidate source,
gateway routing, external reachability, timeouts, and cleanup. Run IPv4 `/32`,
in-prefix gateway, link-local IPv6 gateway, and global IPv6 gateway scenarios
in isolated namespaces before a disposable VPS.

**Acceptance:** two identical runs produce no duplicate content and no needless
file rewrites. Test invalid IPv6, DAD failure, blocked gateway Echo, unreachable
external target, apt failure, partial run, no selected IPv6, and reboot.

## 4. Native MOTD automation

Implement a documented, tested noninteractive lifecycle in
`RzandAl/debian-server-info-motd` first and release it. Update the one source pin,
stage and verify its installer, then call that native interface. Keep
`PrintLastLog` outside the default bootstrap plan.

**Acceptance:** fresh install, matching healthy no-op, repair, upgrade, and
native rollback. Verify state, pinned source, checksums, and `server-info` exit
status. A module failure reports the completed Base stage accurately.

## 5. First apply-capable release

Complete the documented VPS scenario matrix, record what was actually tested,
publish a versioned installer path and checksums, and tag the first supported
release. No `curl | bash` command is advertised before the release is usable.

## Later modules

| Module | Design questions before implementation |
| --- | --- |
| Firewall | nftables ownership, SSH access, IPv4/IPv6 policy, persistence, timed rollback, coexistence with VPN rules |
| VPN | Separate provider/setup choices, secrets and key handling, routing, DNS, integration with firewall, native installer lifecycle |

Neither module is selectable until its contract and tests exist. They will
share collection, planning, recovery, and verification without expanding Base
silently.
