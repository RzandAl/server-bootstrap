# File transactions

`transaction.py` is the internal file backend introduced in `0.3.0-dev`.
The bootstrap wizard and preview still never write target files or create
transaction state. There is no bootstrap `--apply` option. This layer is tested
on temporary roots; it is not the complete network recovery mechanism.

## State and ownership

Production state belongs under `/var/lib/rzandal-server-bootstrap`, owned by
root with mode `0700`. Files have mode `0600`; unsafe existing permissions,
symlinks, hard links, and unexpected owners are rejected, not silently repaired.
The system-root backend requires effective UID 0. Alternate roots and state
paths exist only as test dependency injection; they are not CLI options.

| Path | Purpose |
| --- | --- |
| `lock` | Single process lock shared by preparation, writes, commit, and recovery |
| `active.json` | Durable pointer to the only unresolved run |
| `runs/<run-id>/backup.json` | Immutable originals, candidates, reviewed-plan digest, and watched files/inventories |
| `runs/<run-id>/journal.json` | Phase, attempted writes, backup checksum, and recovery failures |

Run IDs contain 32 lowercase hexadecimal characters. Each state object carries
a SHA-256 checksum; duplicate JSON keys, invalid phases/paths, inconsistent
write intent, and corrupt payloads stop processing before recovery writes.
Checksums detect corruption; private ownership is the trust boundary. Recovery
data can contain user-file content and must never be committed or published.

An unresolved run blocks the next run, including one whose file plan is already
unchanged. Completed backups are retained; a healthy new plan does not create
another run, backup, or target rewrite. No automatic backup pruning exists yet.

## Internal lifecycle

1. `prepare(report, refresh=...)` requires a complete, unblocked preflight plan.
   It reruns the host audit, compares the whole reviewed plan, acquires the
   shared lock, re-audits, and independently checks watched bytes/metadata and
   include inventories. Changed originals are saved before any target write.
   The caller must build a fresh `SystemView` for every audit, not reuse its cache.
2. The future apply supervisor must arm independent recovery before it calls
   `apply_files`. That primitive rechecks the audit and watched state again,
   writes each intent durably, then atomically replaces its target on the same
   filesystem. Temporary files are fsynced before rename, parent directories
   after rename; parent descriptors are pinned and opened without symlink
   traversal. Observed external changes reject a write.
3. Ordinary write failures and Python interruptions attempt immediate file
   recovery. An uncatchable process kill leaves the durable run for a separate
   recovery process. The lock coordinates this project, not external editors.
4. `recover(run_id)` walks attempted writes in reverse. An original already in
   place is left alone; a matching candidate is restored to its original bytes,
   type, target, mode, owner, and mtime, or removed if originally absent.
   An unrelated third version is preserved. Other targets are still recovered,
   failures are recorded, and the active run remains blocked for manual review.
5. `commit(run_id)` is an internal future-supervisor operation, allowed only
   after all candidates still match. It records a terminal state before clearing
   the pointer. A late recovery never undoes a committed run or clears a newer
   active run. The supervisor must perform health and fresh-session connectivity
   checks first; this file backend cannot establish those facts itself.

Extended attributes/ACLs and special permission bits are unsupported. They are
blocked rather than discarded. An inherited ACL on a new temporary file also
stops the write. The current preflight checks existing file attributes; runtime
checks repeat that constraint before backups and writes.

## Console file recovery

For an existing run, from a trusted checkout of this project:

```sh
sudo python3 -I transaction.py status <run-id>
sudo python3 -I transaction.py recover <run-id>
```

Only these operations and help are exposed. Neither command creates a new run,
installs packages, restarts services, changes addresses/routes, or accepts an
arbitrary backup/profile path. `recover` is idempotent and exits with status `2`
on an incomplete recovery, corrupt state, or a held lock. A conflict requires
manual review: restore the desired original or matching candidate, then retry
recovery. Do not delete the active pointer to bypass an unresolved run.

These commands restore files only. A supervised run deliberately refuses bare
file recovery or commit: use `recovery.py recover <run-id>` for its coordinated
file/network lifecycle. The independent supervisor, protected bundle, timer,
and owned-network journal were added in `0.4.0-dev`; see
[Independent recovery](RECOVERY.md). `0.5.0-dev` adds
[fresh SSH acknowledgment](SSH_ACKNOWLEDGMENT.md) for isolated fixtures; final
health is rechecked before terminal commit. `0.6.0-dev` adds an
[owned temporary IPv6 probe](IPV6_PROBE.md) before any permanent writes, with
independent cleanup participating in coordinated recovery. `0.7.0-dev` connects
complete Base fixtures and retained package diagnostics. `force_run=True`
permits a guarded runtime/package-only run with an empty file backup list;
ordinary unchanged file plans still produce no transaction. Production Base
and module wiring remain pending. No VPS reboot guarantee is claimed in this build.

## Verification

Repository tests write only inside temporary target/state roots. They cover
regular files, symlinks, original absence, metadata, binary backups, stale files,
new includes, changed live facts, concurrent processes, corrupt state, partial
failure, fsync failure after replacement, and manual conflict resolution.
Writer subprocesses receive real `SIGKILL` immediately before and after target
replacement; a new process then restores the saved state without assistance
from the writer. Another test passes an actual preflight plan through the file
backend and verifies that the next plan is unchanged.

Debian 13 CI runs the suite both as root and as `nobody`. The root variant also
checks restoration of a different user/group and the actual planner's system
metadata. These checks do not substitute for namespace and disposable-VPS
validation of the production network transition and reboot. The supervisor's
own kernel/systemd tests run separately, as described in the recovery guide.
