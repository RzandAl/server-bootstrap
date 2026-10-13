# Planning and architecture

This is the working design for the apply-capable first release. The current
`0.6.0-dev` build implements collection, validation, read-only host preflight,
exact file candidates, durable file transactions, and independent systemd/network
recovery with fresh SSH acknowledgment and temporary IPv6 probing on isolated
roots and namespaces. The bootstrap CLI does not
execute the production apply workflow yet.

## Scope

The first usable release targets fresh Debian 13 VPS instances using ifupdown,
one primary interface, static IPv4, and optional static IPv6. Its modules are
Base and MOTD. Firewall and VPN remain later milestones.

We standardize server configuration without combining user provisioning,
SSH hardening, firewall rules, or VPN installation into the base operation.
User settings target the invoking account. Direct execution uses the real UID;
a root process with sudo metadata resolves `SUDO_UID` through passwd and checks
`SUDO_USER` and `SUDO_GID` against it. Inconsistent or incomplete metadata is
rejected. An unprivileged process cannot select another account using these
variables. Direct root execution targets root. The passwd home is used instead
of `HOME`; no account-selection question, user creation, key copying, or sudo
permission changes are part of Base.

## Workflow

1. Inspect the host using read-only commands and files.
2. Collect all values and module selections. Do not install dependencies,
   add addresses, restart services, or write configuration during questions.
3. Validate the complete profile and inspect configuration ownership.
4. Stage candidate files and identify exact changes, prerequisites, and
   operations in a complete plan. Staging must not modify target files.
5. Ask once: `Apply? [y/N]`. The default is No. Cancellation leaves the target
   unchanged and removes staging data.
6. Acquire a run lock, recheck that inspected files and live network state have
   not changed, create recovery data, and arm independent network rollback.
7. Run the selected temporary IPv6 probe. Clean up probe-owned state on success,
   failure, cancellation, and interruption. A failed probe stops application.
8. Apply managed changes, verify every module, and record success only after
   connectivity verification from a fresh session. Disarm rollback after that
   recovery acknowledgment.

Temporary IPv6 probing is a mutation. It belongs after the single final
confirmation, even though it precedes permanent IPv6 configuration.
Reconnection acknowledgment completes the network transaction; it is not a
second authorization prompt for additional changes.

The apply-capable release needs a supervisor independent of the current SSH
process, for example a root-owned systemd service plus a rollback timer. A
shell `trap` cannot recover connectivity after its own session or process dies.
Recovery must restore both files and live addresses/routes. Merely restoring
`/etc/network/interfaces` does not restore the running network.

## Profile format

The wizard and JSON input use the same validation model. The JSON schema
version is independent of the project release version. Unknown fields,
duplicate keys, strings in boolean fields, and stale disabled-IPv6 values are
rejected.

The optional legacy `user` field is an assertion about the invoking account,
not an override. A mismatch fails validation. Omit it for reusable profiles.

Example with documentation addresses only:

```json
{
  "schema_version": 1,
  "hostname": "rzandal-host-edge",
  "interface": "ens3",
  "ipv4_cidr": "192.0.2.10/32",
  "ipv4_gateway": "198.51.100.1",
  "ipv6_enabled": true,
  "ipv6_cidr": "2001:db8:1234::2/64",
  "ipv6_gateway": "2001:db8:1234::1",
  "user_timezone": "Europe/Moscow",
  "motd": true
}
```

For IPv4-only setup, set `ipv6_enabled` to `false` and omit `ipv6_cidr` and
`ipv6_gateway`, or set both to `null`. The IPv6 DNS address is then omitted.
This selection concerns static IPv6 configuration; it does not disable the
kernel IPv6 stack. RA, existing IPv6 configuration, and DNS ownership must be
audited before applying the IPv4-only profile.

Do not commit real profiles, server addresses, recovery data, or logs. This
repository's examples use reserved documentation prefixes.

## Validation

Validation has three distinct layers:

| Layer | Checks | Current status |
| --- | --- | --- |
| Value validation | Short hostname, Linux interface name, account name, complete IP parser, numeric prefixes, address families, known timezone | Implemented |
| Host eligibility | Debian 13, invoking account/home, prerequisites, locale, live interface/routes, network/DNS/APT ownership | Implemented for the supported static ifupdown subset; unsupported migrations blocked |
| Connectivity | DAD, gateway routing/NDP, candidate-bound external TCP, new SSH session | Implemented in supervised fixtures; production wiring and VPS validation pending |

`ipaddress` rejects the previous `22a12:...` typo because an IPv6 hextet may not
contain five hexadecimal digits. CIDR values must use numeric prefixes, not
dotted netmasks. Network/broadcast IPv4 addresses are rejected for prefixes
shorter than `/31`. A `/31` is valid, and an IPv4 gateway may legitimately lie
outside a VPS `/32` prefix.

Link-local IPv6 gateways such as `fe80::1` are valid. The interface is supplied
separately; scoped input containing `%ens3` is not accepted. A global gateway
outside the prefix requires provider-specific routing verification.

Never run user-supplied shell snippets, `eval` a profile, or `source` a data
file. Subprocesses receive validated argument arrays. Validation must not rely
only on regular expressions for IP addresses.

## Network ownership and routing

Read `/etc/network/interfaces` and all included fragments before deciding which
stanzas belong to the selected interface. Preserve unrelated interfaces and
loopback. Existing duplicate, generated, or complex stanzas require review;
never overwrite the whole file and silently discard them.

Detect ifupdown, active systemd-networkd/NetworkManager ownership, and cloud-init
generation. A cloud-init image can regenerate networking and hostname after
reboot. If migrating, include the precise generated fragments and cloud-init
settings in the reviewed plan and backups. Do not disable all of cloud-init.
Unsupported ownership combinations must stop preflight rather than receive a
best-effort rewrite.

Interface discovery first examines the route to the current SSH client. If it
cannot use that, it accepts only an unambiguous default-route interface or a
single non-loopback interface. `ens3` is a usual value, not proof of ownership.
Multiple addresses or gateways remain explicit choices rather than guesses.

For IPv4 `/32` with an off-link gateway, the final backend must install an
explicit reachable route to that gateway or a verified equivalent provider
configuration before the default route. The planner identifies this case;
the staged `/32` candidate uses ifupdown `pointopoint` before `gateway`.
Debian CI validates its syntax with `ifquery` and exercises owned `/32` kernel
transitions in namespaces; full provider/ifupdown transition validation remains
pending on a VPS. Other off-link IPv4 prefixes and global
off-link IPv6 gateways block staging.

Do not run a blind `systemctl restart networking` over SSH. Plan the exact
transition with rollback and preserve the route carrying the current session
until the candidate path has been verified.

Fresh acknowledgment uses protected OpenSSH process ancestry and its live kernel
TCP socket. The authenticated account must match the original invoking account,
the server endpoint must be a planned candidate address, and the per-connection
monitor must have started after application completed. An old SSH transport,
including a new multiplexed channel, cannot commit. Final file/network health
and both deadlines are checked before durable terminal state and timer cleanup.
[SSH acknowledgment](SSH_ACKNOWLEDGMENT.md) describes the fixture-only contract.

## IPv6 probe contract

The internal probe snapshots existing addresses, routes, neighbor information needed
for diagnosis, and relevant interface state before it makes changes.

- Add only the candidate address if it is absent. Reuse an existing identical
  address without claiming ownership of it.
- Wait with a bounded timeout for DAD. Reject `dadfailed`, and never treat
  `tentative` as a successful result.
- Test the candidate source address explicitly. Testing the current default
  path or an older working IPv6 address can produce a false positive.
- Verify routing to the gateway and the external target separately. A gateway
  may block ICMP Echo; do not equate an unanswered ping with an invalid gateway.
- Use an unused temporary routing table and a rule requiring both the candidate
  source and an owned packet mark. Bind TCP to the address, interface and mark;
  ordinary unmarked traffic keeps its original routing policy.
- Delete only addresses, routes, and rules created by this run. Preserve any
  preexisting state, including an identical address or gateway route.
- On inconclusive external checks, stop without writing permanent IPv6.
  There is no silent fallback to "validated" or to disabling selected IPv6.

Success requires completed DAD, the intended marked route, resolved gateway
NDP, and at least one successful TCP connection to the two planned destinations:
Cloudflare `[2606:4700:4700::1111]:443` and Quad9 `[2620:fe::10]:53` (IPv6 address
and port are separate typed fields). New addresses use `noprefixroute` and
`preferred_lft 0`; existing identical addresses are reused unchanged. Cleanup
must finish before any permanent files or live transition. The bootstrap CLI
only discloses this plan; traffic is currently sent only by supervised fixtures.
[IPv6 probe](IPV6_PROBE.md) details endpoints, ownership and failure behavior.

## DNS, locale, and timezones

The base profile uses a regular static `/etc/resolv.conf`, with IPv4 DNS
`1.1.1.1` and `9.9.9.10`, plus `2606:4700:4700::1111` when static IPv6 is selected.
Identify symlink targets, DHCP hooks, resolvconf/openresolv, and
systemd-resolved ownership before replacing anything. Relevant ownership
changes belong in the plan. Do not merely unlink a resolver file while its
manager remains active, and do not use `chattr +i` to hide the conflict.

The system uses `C.UTF-8` and `UTC`. Do not generate extra locales or make
`LC_ALL` a permanent system setting. Audit existing `LANGUAGE`, `LC_ALL`, and
category overrides, including the earlier `LC_TIME=ru_RU.UTF-8`, so unsupported
old settings cannot survive unnoticed.

The invoking account gets a single managed `export TZ=Europe/Moscow` block in
its real home directory's `.profile`. Preserve unrelated content and ownership.
The pure renderer already replaces its own block without appending duplicates
and rejects malformed markers. The renderer stays pure; the internal file
backend is separate. Preflight conservatively
blocks unmanaged `TZ`, `LANG`, `LANGUAGE`, or `LC_*` assignments in inspected
startup files, and an existing `.bash_profile` or `.bash_login` under Bash.
It preserves those files for explicit review rather than guessing shell flow. This setting governs that account's login-shell environment; it
does not change service or cron timezones.

Keep `/etc/hostname` and local hostname resolution in `/etc/hosts` consistent,
preserving unrelated aliases and mappings.

## APT and packages

The starting profile uses the three explicit `trixie`, `trixie-security`, and
`trixie-updates` binary repositories with `main non-free-firmware`, matching
the components observed in our recent Debian installation. Source indexes,
backports, `contrib`, and `non-free` are not added.

The canonical destination is `/etc/apt/sources.list`, matching the agreed
minimal base scheme. Preflight parses active `.list` and deb822 `.sources`
files, removes the standard Debian binary/source entries from their old
locations, and emits one managed block with the three binary sources.
Third-party entries, comments outside removed source paragraphs, and disabled
deb822 paragraphs are preserved. Mixed official/third-party URI paragraphs,
nonstandard Debian suites, malformed entries, source symlinks, and custom APT
source-path overrides require review and block the file plan. The still-supported
legacy-list format is a deliberate project choice; deb822 input is supported.

Use `apt-get update` and `apt-get install` in the apply engine. Installing
missing selected packages is naturally repeatable; do not upgrade the entire
system or remove packages as an incidental part of bootstrap.

Keep Python, timezone data, iproute2, ifupdown, and CA-certificate prerequisites
distinct from the convenience package list. If a prerequisite is unavailable
at collection time, exit with an explicit prerequisite message. Never install
it while asking questions.

## MOTD integration

`MOTD_SOURCE_REF` in `bootstrap.py` pins the current verified upstream release
`v0.3.1` in one place. Use the same immutable release selection for the
installer and its payload. Download into staging, verify the expected content
and checksum, validate Bash syntax, and only then execute the native installer.
Do not stream a moving `main` script directly into a root shell.

The existing release uses `/dev/tty`, its own menu, and its own confirmations.
It accepts `--source-ref` and `--debug`, but has no documented automatic-install
mode. Therefore, "native installer plus one bootstrap confirmation" requires
a supported noninteractive install/update/repair interface in the MOTD project
and a tested release containing it. We will not imitate keypresses, scrape
menus, invent a `--yes` flag, or duplicate its installation internals here.

Until that dependency is ready, MOTD apply remains unavailable. The selected
module is shown as a plan only. The current source pin is an integration
baseline, not a claim that unattended installation already works.

An integrated run must verify native installation state, expected source ref,
managed checksums, presence of `/usr/local/bin/server-info`, and a successful
bounded `server-info` invocation. A matching healthy installation is a no-op;
missing or modified managed files follow the native repair lifecycle.
OpenSSH `PrintLastLog` management must stay unselected unless it appears
explicitly in the collected plan.

## Current host-plan coverage

`--inspect` invokes the read-only audit; `--diff` additionally displays unified
diffs. JSON includes exact candidates, file types, ownership/mode, content
hashes, and inode/mtime fingerprints of inspected files. Included directories
and glob results are recorded too, so a future apply can detect newly added
fragments. No staging directory, backup, package operation, hook, service
restart, address addition, DAD test, or external probe runs from the bootstrap
CLI. The internal file backend is exercised separately in isolated tests.

The supported subset is Debian 13, active ifupdown, one plain Ethernet primary
interface, simple static/manual stanzas, and an unmanaged regular resolver.
The audit follows bounded relative/absolute `source` and `source-directory`
includes with Debian's filename filtering. It preserves other interfaces and
retains supported MTU, metric, and MAC options for the selected interface.

Cycles/repeated includes, symlinks, duplicate address stanzas, mappings,
renames, lifecycle hooks in the selected stanza, templates, inline comments,
continuations, DHCP/SLAAC, cloud-init presence, custom policy rules, active
alternate managers, resolver lifecycle packages, unsafe file types, and
unsupported extended attributes/ACLs block
staging. Cloud-init migration is not guessed from partial YAML parsing.
A generated resolver is not silently unlinked. Missing tools/packages and an
unavailable C.UTF-8 locale also block staging; collection installs nothing.

All candidates are withheld if any blocker is found. This is an eligibility
and file-plan check, not proof of connectivity or an apply-ready transaction.
Global hook/package effects, full provider routing, command-line and external
locale/environment sources, production supervisor wiring, fresh SSH acknowledgment,
and live VPS transition verification remain part of the apply milestone. File
plans contain machine-specific data and must remain outside Git.

## Idempotency and recovery

Idempotency is an acceptance condition for the first apply-capable release.
Repeated planning is deterministic. Tests simulate writing the candidate
files to isolated fixtures and confirm that the next plan has no changed
files, including managed blocks, normalized APT sources, and the UTC symlink.
The transaction backend also consumes an actual preflight plan in a fixture,
commits it, and confirms a second plan creates no state or target rewrites.
System-wide idempotency has not been implemented or tested.

- Compare candidate content and metadata before writing. Healthy unchanged
  targets do not get a new backup or modified timestamp.
- Back up each changed regular file or symlink with its original type, target,
  owner, mode, and absence/presence. Store recovery data under a root-only
  project state directory with unique run IDs.
- Write candidate regular files atomically on the target filesystem. Never
  follow an unexpected symlink while replacing a managed file.
- Record owned changes and completion steps. Do not consider a version marker
  alone proof of success.
- Restore original absence by removing only a file created by this run;
  preserve unrelated files and any preexisting network state.
- Recover configuration and live networking separately. Explicitly report any
  partial recovery failure and keep recovery data for a console repair.
- Package installation is not a fully reversible file transaction. Preserve
  installed packages if a later module fails; report the completed steps.
- A MOTD failure uses its native recovery lifecycle and leaves a verified Base
  stage intact. Do not undo working networking solely because a later module
  failed.

Concurrent runs require a single project lock and an explicit stale-run
recovery path. No apply-capable release will be tagged until interrupted runs,
second runs, and reboot persistence have been tested on a disposable VPS.

The file part of this design is implemented in `transaction.py`; see
[File transactions](TRANSACTIONS.md) for its state format, tested interruption
cases, console recovery, and the live-network guarantees still pending.

`recovery.py` now supplies protected worker bundles, independent deadlines,
combined file/network recovery, and early-boot file restoration.
`network_recovery.py` records static-address and main-table route deltas,
preserving reused objects and refusing observed external conflicts. See
[Independent recovery](RECOVERY.md) for the supported subset and verification.
Detached application and commit are restricted to fixture roots. They cannot
authorize or enable production Base through a command-line flag.

## Sources

- [Debian trixie ifupdown interfaces(5)](https://manpages.debian.org/trixie/ifupdown/interfaces.5.en.html)
- [Debian trixie APT sources.list(5)](https://manpages.debian.org/trixie/apt/sources.list.5.en.html)
- [cloud-init network configuration](https://docs.cloud-init.io/en/latest/reference/network-config.html)
- [MOTD v0.3.1 installer contract](https://github.com/RzandAl/debian-server-info-motd/blob/v0.3.1/docs/INSTALLER.md)

## Commit identity

Use the actual primary author and include the other project author as a
co-author. Both use their verified GitHub noreply address:

| Author | Address |
| --- | --- |
| Leya / AmleyID | `324701712+AmleyID@users.noreply.github.com` |
| RazisID12 | `182811733+RazisID12@users.noreply.github.com` |

For changes authored primarily by Leya, include:

```text
Co-authored-by: RazisID12 <182811733+RazisID12@users.noreply.github.com>
```

Local signed commits use the actual author's signing identity. GitHub web
commits may use GitHub's verified web-flow signature and committer identity.
