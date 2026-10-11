# Planning and architecture

This is the working design for the apply-capable first release. The current
`0.1.0-dev` build implements collection, validation, planning, and a pure
managed-profile renderer only. None of the apply procedures below runs yet.

## Scope

The first usable release targets fresh Debian 13 VPS instances using ifupdown,
one primary interface, static IPv4, and optional static IPv6. Its modules are
Base and MOTD. Firewall and VPN remain later milestones.

We standardize server configuration without combining user provisioning,
SSH hardening, firewall rules, or VPN installation into the base operation.
The named account must already exist. We never infer sudo access or copy SSH
keys from root merely because the account name was entered.

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

Example with documentation addresses only:

```json
{
  "schema_version": 1,
  "hostname": "rzandal-host-edge",
  "interface": "ens3",
  "user": "razis",
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
| Host eligibility | Debian 13, existing interface/account, available tools and locale, ownership of network/DNS/APT | Basic observations only; full preflight pending |
| Connectivity | DAD, gateway routing, external reachability, new SSH session | Pending; never inferred from valid syntax |

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
the actual ifupdown method is pending namespace and VPS validation.

Do not run a blind `systemctl restart networking` over SSH. Plan the exact
transition with rollback and preserve the route carrying the current session
until the candidate path has been verified.

## IPv6 probe contract

The probe must snapshot existing addresses, routes, neighbor information needed
for diagnosis, and relevant interface state before it makes changes.

- Add only the candidate address if it is absent. Reuse an existing identical
  address without claiming ownership of it.
- Wait with a bounded timeout for DAD. Reject `dadfailed`, and never treat
  `tentative` as a successful result.
- Test the candidate source address explicitly. Testing the current default
  path or an older working IPv6 address can produce a false positive.
- Verify routing to the gateway and the external target separately. A gateway
  may block ICMP Echo; do not equate an unanswered ping with an invalid gateway.
- Prefer a temporary routing table and source-specific policy rule for an
  external probe. Do not replace the existing default route merely to test a
  candidate address.
- Delete only addresses, routes, and rules created by this run. Preserve any
  preexisting state, including an identical address or gateway route.
- On inconclusive external checks, stop without writing permanent IPv6.
  There is no silent fallback to "validated" or to disabling selected IPv6.

The exact probe destinations and success policy must be finalized before
implementing apply. This build does not send probe traffic.

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

The selected account gets a single managed `export TZ=Europe/Moscow` block in
its real home directory's `.profile`. Preserve unrelated content and ownership.
The pure renderer already replaces its own block without appending duplicates
and rejects malformed markers. It does not write files yet. Preflight must
report conflicting existing `TZ` assignments or a `.bash_profile` that bypasses
`.profile`. This setting governs that account's login-shell environment; it
does not change service or cron timezones.

Keep `/etc/hostname` and local hostname resolution in `/etc/hosts` consistent,
preserving unrelated aliases and mappings.

## APT and packages

The starting profile uses the three explicit `trixie`, `trixie-security`, and
`trixie-updates` binary repositories with `main non-free-firmware`, matching
the components observed in our recent Debian installation. Source indexes,
backports, `contrib`, and `non-free` are not added.

The initial planned destination remains `/etc/apt/sources.list`. Preflight must
also parse `.list` and deb822 `.sources` files in `/etc/apt/sources.list.d`, so
official sources are normalized without duplication. Preserve third-party
entries unless a precise, reviewed migration requires otherwise. APT now
recommends deb822 for new source files; choosing a canonical deb822 destination
is an open implementation decision, not an automatic format migration in this
planning build.

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

## Idempotency and recovery

Idempotency is an acceptance condition for the first apply-capable release.
Repeated planning is already deterministic, and the profile-block renderer is
already repeatable. System-wide idempotency has not been implemented or tested.

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
