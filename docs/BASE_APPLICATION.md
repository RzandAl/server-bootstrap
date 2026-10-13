# Reviewed Base application

`0.7.0-dev` connects the complete Base plan to the independent supervisor in
protected fixture roots. The public wizard still only collects and previews;
there is no production `--apply` command. Runtime hostname and package mutations
explicitly reject the system root. MOTD must be deselected for these fixtures
until its native noninteractive lifecycle is ready.

## Application order

`prepare_review` combines the exact preflight file plan with typed live network,
runtime hostname, dpkg inventory/audit, invoking account, and actual SSH origin
when present. A stale origin or changed package inventory stops arming. Profile
data cannot provide shell commands, executable paths, APT options or evidence.

`launch_reviewed` prints the profile, exact file diff, runtime hostname change
and package-retention policy, then asks one `Apply? [y/N]`. Declining leaves
target files and networking unchanged and creates no recovery state. An accepted
plan is freshly audited and backed up, then independently guarded before writes.

The detached writer checks selected IPv6 first and cleans its owned temporary
probe. It applies candidate files and the immediate network operations, changes
the runtime hostname, updates APT indexes and installs missing Base packages.
Complete file, network, hostname and package health must pass before the run
becomes ready for a fresh SSH acknowledgment. Guard/deadline checks surround
the package steps; a ready marker alone cannot establish success.

## Network completion

New addresses are added while original addresses remain. A verified originating
SSH connection can receive an owned temporary host route preserving its old
return path while defaults change. An identical existing route is reused. Only
this run's temporary route is removed during completion.

Old addresses and owned temporary SSH routing are removed inside acknowledgment,
after proving a new authenticated transport to a candidate address. Final
file/network/hostname/package health, SSH evidence and deadlines are checked
again before durable commit. Failure during these deferred changes leaves
independent recovery armed and restores recorded originals.

The Base subset has at most one static global address/default per family.
Changing an existing address's prefix, or moving IPv4 within the same prefix,
requires a separately designed migration and is refused. The latter avoids
primary/secondary address deletion removing a newly added candidate. Complex
policy routes and alternate managers remain outside the supported plan.

## Packages stay installed

The package journal observes execution; it is not a package rollback plan.

| Operation | Policy |
| --- | --- |
| Index refresh | `apt-get -o APT::Update::Error-Mode=any update`; failure stops installation |
| Installation | Missing names from the fixed nine-package Base set only; `--yes --no-install-recommends --no-upgrade --no-remove` |
| Existing Base packages | Healthy installed packages, including held packages, are reused |
| Dependencies | APT resolves them normally; their installation/version changes are retained too |
| Recovery | Read-only dpkg inventory and audit after stopping the writer; no remove, purge, downgrade, reinstall or automatic repair |
| Indexes/cache | Retained; restoring reviewed source files does not roll back APT's data directories |

The private `packages.json` records package versions/statuses before and after,
durable step intent, return codes and bounded output tails. A killed install
can remain at `intent`; completion is never inferred from that marker. The
entire owned writer cgroup, including apt/dpkg/hook children, is stopped before
coordinated settings recovery acquires the project lock.

An incomplete or unreadable package state sets `manual_attention`. Files,
network and runtime hostname can still be successfully restored and the active
run cleared. Package health must be repaired manually before a new Base run or
healthy acknowledgment. `recovery.py status <run-id>` and recovery output include
the retained-package policy, step states and manual-attention flag; full APT
output remains in private state.

Each APT command has a bounded timeout and a minimal fixed environment. The
reviewed host's existing package hooks are not sandboxed by these safeguards;
their full effects remain part of production acceptance.

## Repeated runs and verification

An identical healthy second run does not rewrite files, duplicate profile
blocks, recreate unchanged addresses or change a matching hostname. A guarded
runtime/package-only run can have an empty file backup list. It refreshes
indexes; installation is skipped when all nine Base packages are healthy.

Debian 13 CI copies a package-equipped target root with `ccze` deliberately
absent and builds an offline index of its real Debian package. It uses owned
network/UTS namespaces and actual systemd recovery and OpenSSH acknowledgment.
Fixtures explicitly seed the current supported regular locale/shell-file
subset; package-owned aliases in a fresh image remain a production acceptance
item. Fixture writes refuse symlinks instead of following them into the
container's own `/etc`.

Native scenarios check successful installation and fresh SSH, a second run
without file rewrites, failed update, deadline recovery retaining installed
`ccze`, and SIGKILL while APT has a waiting child. Regressions additionally check
partial package installation, unhealthy retained state, hostname conflicts and
changed namespace identity, decline/stale plans, and SSH loss after deferred
network changes.

These checks establish the fixture lifecycle. Full ifupdown/provider behavior,
arbitrary hooks, module integration and a healthy VPS reboot remain required
before an apply-capable release.

Primary references: [apt-get(8)](https://manpages.debian.org/trixie/apt/apt-get.8.en.html)
and [dpkg(1)](https://manpages.debian.org/trixie/dpkg/dpkg.1.en.html).
