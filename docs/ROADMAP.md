# Roadmap

## Foundation — current development build

- [x] Shared README structure, explicit compatibility, MIT, and joint authorship.
- [x] Central defaults and one MOTD source-ref constant.
- [x] Typed profile with strict full-address validation and canonical IP output.
- [x] Read-only interactive collection and text/JSON plan.
- [x] SSH-route/default-route interface discovery without ambiguous address guesses.
- [x] Basic local prerequisite observations, explicitly distinct from full preflight.
- [x] Pure managed `.profile` timezone renderer with repeated-run checks.
- [x] Automated tests and a Debian 13 CI workflow.

This build deliberately has no apply option and is not a production release.

## 1. Complete host preflight and staged file plan

Inspect Debian 13, existing account and home, available `C.UTF-8`, prerequisites,
network managers, cloud-init, resolver ownership, includes, and all active APT
sources. Keep unsupported migrations explicit. Finalize legacy-list versus
deb822 output and the exact IPv4 `/32` route method.

**Acceptance:** collect and stage without target changes; reject unsupported
ownership; preserve unrelated fragments; show exact file changes, package
operations, resolver and cloud-init ownership changes, and the single final
confirmation. A cancelled run leaves target bytes and live networking intact.

## 2. Transaction and network recovery

Add a single-run lock, root-only state, backups including file types and
metadata, atomic writes, an independent apply service and rollback timer,
and a new-session acknowledgment of connectivity. Recheck staged assumptions
before applying. Document a console recovery command.

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
