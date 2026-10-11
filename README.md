# RzandAl Server Bootstrap

Interactive base configuration for fresh Debian 13 VPS instances, followed by
optional RzandAl modules.

The project turns our manual server setup into a validated, repeatable workflow:
collect settings, review the complete plan, confirm once, and apply with
backups and recovery.

> **Target platform:** Debian 13 (trixie), with ifupdown networking.
>
> **Development status:** `0.1.0-dev` implements a read-only planning wizard.
> Applying configuration, installing packages, and installing modules are not
> implemented yet. No production release is available.

## Highlights

- Collects hostname, interface, existing account, static IPv4, optional static
  IPv6, gateways, and user timezone.
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
- Provides a repeatable managed `.profile` timezone-block renderer for the
  future apply engine; it preserves content outside its own block.

## Standard profile

| Setting | Default or policy |
| --- | --- |
| System locale | `C.UTF-8`; no additional locales generated |
| System timezone | `UTC` |
| User | Existing `razis` account |
| User timezone | `Europe/Moscow` through a managed `.profile` block |
| Interface | Autodetect; `ens3` is the usual deployment interface |
| IPv4 DNS | `1.1.1.1`, `9.9.9.10` |
| IPv6 DNS | `2606:4700:4700::1111`, when static IPv6 is selected |
| DNS management | Static `/etc/resolv.conf`, after an ownership audit |
| Debian suites | `trixie`, `trixie-security`, `trixie-updates` |
| Debian components | `main non-free-firmware`; no `deb-src` or backports |
| MOTD | Selected by default; pinned to `v0.3.1` |
| Firewall and VPN | Future modules, unavailable in this build |

The planned base package set is `curl`, `git`, `rsync`, `jq`, `unzip`, `htop`,
`mtr-tiny`, `tcpdump`, and `ccze`.

The runtime and apply prerequisites are separate from that convenience package
set. Planning needs Python 3.11 or newer and installed timezone data. Interface
autodetection uses `iproute2` when available. The future apply engine will also
require ifupdown and working CA certificates; the existing MOTD installer needs
`wget` and its documented core utilities.

## Compatibility

| Area | Target or verified environment |
| --- | --- |
| Apply target | Debian 13 (trixie), single primary VPS interface, ifupdown |
| Planner runtime | Linux, Python 3.11 or newer, installed IANA timezone data |
| Network profiles | Static IPv4, including `/32`; optional static IPv6 |
| Local validation | Automated parser, planning, discovery, and profile-block tests |
| CI | The same tests in a Debian 13 container |
| Live VPS apply | Pending; no apply implementation exists yet |

The initial scope uses an existing account. Creating users, adding SSH keys,
changing sudo rights, and changing SSH authentication are separate decisions.
Other network managers require an explicit migration design.

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
```

Keep machine-specific profiles outside Git; `/profiles/` is ignored.
The profile format and a documentation-address example are in
[Planning and architecture](docs/ARCHITECTURE.md#profile-format).

## Modules

| Module | Scope | Status |
| --- | --- | --- |
| Base | Hostname, network, DNS, locale, timezones, APT sources, packages | Planner available; apply pending |
| MOTD | [Debian Server Info MOTD](https://github.com/RzandAl/debian-server-info-motd) through its native installer | Pinned integration planned |
| Firewall | Separate, explicit rules and recovery | Future |
| VPN | Separate VPN installation and configuration | Future |

## Documentation

- [Planning, validation, ownership, recovery, and module contracts](docs/ARCHITECTURE.md)
- [Implementation milestones and acceptance criteria](docs/ROADMAP.md)
- [Continuous integration checks](.github/workflows/ci.yml)

## Tests and validation

Run the repository-owned checks without root:

```sh
python3 -m unittest discover -s tests -v
python3 bootstrap.py --help
```

Tests cover malformed and mixed-family IP addresses, the previous oversized
IPv6-hextet typo, gateway semantics, strict JSON input, disabled IPv6, interface
discovery, shell-sensitive input, and repeated managed-profile rendering.
Network rollback and real VPS installation must pass their own checks before
an apply-capable release is published.

## Maintainers

Developed and tested together by [AmleyID](https://github.com/AmleyID) and
[RazisID12](https://github.com/RazisID12).

## License

[MIT](LICENSE)
