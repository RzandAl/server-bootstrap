# RzandAl Server Bootstrap

Interactive base configuration for fresh Debian 13 VPS instances, followed by
optional RzandAl modules.

The project turns our manual server setup into a validated, repeatable workflow:
collect settings, review the complete plan, confirm once, and apply with
backups and recovery.

> **Target platform:** Debian 13 (trixie), with ifupdown networking.
>
> **Development status:** `0.8.0-dev` connects reviewed Base fixtures to native
> MOTD automation after fresh SSH commit. Installer and payload are independently
> pinned to the same released commit. Module failure preserves Base; interruption
> is reported without automatic retries. Packages are retained after recovery.
> Production Bootstrap apply remains pending VPS acceptance.
> No production release is available.

## Highlights

- Collects hostname, interface, static IPv4, optional static IPv6, gateways,
  and user timezone; the timezone target is the invoking account.
- Detects the interface used to reach the SSH client when possible, then falls
  back to an unambiguous default-route interface.
- Validates complete IPv4 and IPv6 addresses with Python's standard `ipaddress`
  parser, including prefix lengths and address families.
- Accepts VPS IPv4 `/32` profiles with an off-link gateway and identifies the
  additional routing requirement in the plan.
- Supports link-local IPv6 gateways with a separately selected interface.
- Produces a complete text or JSON plan without changing the system.
- Keeps MOTD selection and its pinned source reference separate from future
  firewall and VPN modules.
- Resolves direct and sudo callers through passwd, using their real home.
- Audits OS, prerequisites, services, resolver ownership, live addresses/routes,
  ifupdown includes, APT sources, and shell timezone/locale conflicts.
- Produces exact file candidates, metadata, fingerprints, and unified diffs.
- Preserves unrelated interfaces, third-party repositories, and user content;
  unsupported ownership or migration blocks the entire file plan.
- Tests private backups, a single-run lock, stale-plan rejection, atomic file
  replacement, and recovery by a separate process after writer interruption.
- Preserves external edits during recovery and blocks further runs until an
  incomplete recovery is resolved.
- Arms protected worker bundles, independent rollback deadlines, and early-boot
  file restoration; journals owned static address/main-route changes.
- Verifies a new authenticated OpenSSH transport to a candidate address before
  disarming recovery; a new channel on an old ControlMaster transport is refused.
- Checks candidate IPv6 DAD, gateway NDP, and source-bound external TCP under
  the independent guard; removes its temporary address/routes/rule before files.
- Applies reviewed Base fixtures after one effective confirmation; retains old
  addresses until fresh SSH acknowledgment and checks complete Base health.
- Journals strict APT update and missing-package installation; restores settings
  independently and reports retained package state requiring manual attention.
- Reviews native MOTD JSON health before confirmation, then installs, updates,
  repairs or checks the pinned release only after Base fresh SSH commit.
- Serializes an unresolved MOTD module against new Base runs; independently
  observes worker interruption and preserves committed Base and SSH settings.

## Standard profile

| Setting | Default or policy |
| --- | --- |
| System locale | `C.UTF-8`; no additional locales generated |
| System timezone | `UTC` |
| User | Invoking account; original caller under `sudo`, root on direct root launch |
| User timezone | `Europe/Moscow` through a managed `.profile` block |
| Interface | Autodetect; `ens3` is the usual deployment interface |
| IPv4 DNS | `1.1.1.1`, `9.9.9.10` |
| IPv6 DNS | `2606:4700:4700::1111`, when static IPv6 is selected |
| DNS management | Static `/etc/resolv.conf`, after an ownership audit |
| Debian suites | `trixie`, `trixie-security`, `trixie-updates` |
| Debian components | `main non-free-firmware`; no `deb-src` or backports |
| MOTD | Selected by default; pinned to `v0.4.0` and its exact commit/checksums |
| Firewall and VPN | Future modules, unavailable in this build |

The planned base package set is `curl`, `git`, `rsync`, `jq`, `unzip`, `htop`,
`mtr-tiny`, `tcpdump`, and `ccze`.

The runtime and apply prerequisites are separate from that convenience package
set. Planning needs Python 3.11 or newer and installed timezone data. Interface
autodetection uses `iproute2` when available. The future apply engine will also
require ifupdown and working CA certificates. The MOTD module uses its verified
local source API and documented core utilities, including `flock` and `timeout`;
it does not require `wget` for local installation.

## Compatibility

| Area | Target or verified environment |
| --- | --- |
| Apply target | Debian 13 (trixie), single primary VPS interface, ifupdown |
| Planner runtime | Linux, Python 3.11 or newer, installed IANA timezone data |
| Network profiles | Static IPv4, including `/32`; optional static IPv6 |
| Local validation | Automated parser, host-audit, preservation, and repeat-planning tests |
| CI | Debian 13 root/user regressions, native Base/APT/hostname/MOTD fixtures, kernel recovery, real OpenSSH reconnects, and routed IPv6 probes |
| Live VPS apply | Pending; internal file writes are not connected to the bootstrap CLI |

The account is detected, not selected or created. `USER`, `LOGNAME`, and `HOME`
are not account authorities. Consistent `SUDO_UID`, `SUDO_GID`, and `SUDO_USER`
identify the original caller when running as root through sudo. A saved
profile may omit `user`; if present, it must match that caller.

Host file planning currently supports static/manual ifupdown on a plain VPS
Ethernet interface with a regular resolver file. DHCP/SLAAC migrations,
cloud-init, active alternate managers, custom policy routing, and complex
ifupdown stanzas stop preflight with an explanation. Locale and
shell-file symlinks also stop preflight. Production apply remains pending.

## Quick use

From a local checkout, start the planning wizard:

```sh
python3 bootstrap.py
```

No root privileges are needed. Questions collect settings only; the wizard
ends with a preview and does not ask for an ineffective apply confirmation.

Validate and preview a saved profile:

```sh
python3 bootstrap.py --config profiles/server.json
python3 bootstrap.py --config profiles/server.json --json
python3 bootstrap.py --config profiles/server.json --inspect
python3 bootstrap.py --config profiles/server.json --diff
```

`--inspect` runs host preflight and lists exact candidate files. `--diff` also
prints their unified diffs; `--inspect --json` includes their complete content
and inspected fingerprints. Candidates remain in memory. Exit status `2` means
invalid input or a blocked host plan; no candidate files are returned for a
blocked host. Nothing is applied, and no confirmation is requested yet.

Keep machine-specific profiles and generated host plans outside Git; `/profiles/` is ignored.
The profile format and a documentation-address example are in
[Planning and architecture](docs/ARCHITECTURE.md#profile-format).

## Modules

| Module | Scope | Status |
| --- | --- | --- |
| Base | Hostname, network, DNS, locale, timezones, APT sources, packages | Guarded application verified in isolated roots; production pending |
| MOTD | [Debian Server Info MOTD](https://github.com/RzandAl/debian-server-info-motd) through its native installer | Pinned native fixture lifecycle; production pending |
| Firewall | Separate, explicit rules and recovery | Future |
| VPN | Separate VPN installation and configuration | Future |

## Documentation

- [Planning, validation, ownership, recovery, and module contracts](docs/ARCHITECTURE.md)
- [Implementation milestones and acceptance criteria](docs/ROADMAP.md)
- [File transaction state, recovery, and current limits](docs/TRANSACTIONS.md)
- [Independent systemd recovery and owned network changes](docs/RECOVERY.md)
- [Fresh SSH acknowledgment and terminal health checks](docs/SSH_ACKNOWLEDGMENT.md)
- [Temporary IPv6 checks, success policy, and owned cleanup](docs/IPV6_PROBE.md)
- [Reviewed Base application and retained-package policy](docs/BASE_APPLICATION.md)
- [Pinned native MOTD lifecycle after Base commit](docs/MOTD_MODULE.md)
- [Continuous integration checks](.github/workflows/ci.yml)

## Tests and validation

Run the repository-owned checks:

```sh
python3 -m unittest discover -s tests -v
python3 bootstrap.py --help
python3 transaction.py --help
python3 -I recovery.py --help
```

Tests cover malformed and mixed-family IP addresses, the previous oversized
IPv6-hextet typo, gateway semantics, strict JSON input, disabled IPv6, interface
discovery, sudo identity, network includes, both APT source formats, preserved
third-party content, unsupported migrations, zero target writes, and a second
plan after a simulated application producing no changed files. An actual
`ifquery` check runs in Debian CI and is skipped locally if unavailable.
File-transaction tests cover partial writes, `SIGKILL` before and after atomic
replacement, recovery by another process, stale files/include inventories/live
facts, locks, corrupt state, private permissions, preserved metadata, external
edits, and a healthy second plan with no backups or rewrites. Tests write only
to isolated temporary roots. Two metadata/integration cases require root and
are skipped for ordinary users; Debian CI runs both variants.
The supervisor requires a working system manager and system D-Bus; collection
never installs these prerequisites. A separate CI job runs an isolated Debian
systemd container with namespace IPv4/IPv6 changes, timer recovery after client
exit, worker `SIGKILL`, timer disarming, `/24` and `/32` peer restoration, real
OpenSSH IPv4/IPv6 reconnects, sudo identity, ControlMaster refusal, and early-boot
recovery after manager restart. Routed IPv6 cases verify actual DAD failure,
link-local/global gateways, blocked Echo, candidate-bound TCP, a working old
source with a failing new source, reused addresses, and interrupted-probe cleanup.
Native Base fixtures additionally check real APT installation, failed update,
deadline recovery retaining installed packages, an interrupted APT child,
isolated runtime hostname, fresh SSH completion, and unchanged second-run files.
Real VPS connectivity and reboot
validation remain necessary before an apply-capable release is published.

## Maintainers

Developed and tested together by [AmleyID](https://github.com/AmleyID) and
[RazisID12](https://github.com/RazisID12).

## License

[MIT](LICENSE)
