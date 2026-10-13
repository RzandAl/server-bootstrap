# Native MOTD module

`0.8.0-dev` connects the released MOTD API to reviewed Base fixtures. The public
wizard remains read-only and native application to `/` is explicitly rejected.

## Source and review

`bootstrap.py` holds one source ref, `v0.4.0`, and the central `MOTD_RELEASE`
record: exact commit, derived version and independent hashes for installer,
VERSION, manifest, payload and manual command. Every download uses verified
joint commit `5aa02b8ec48feca8cf0be10d65df79da77d1bb62`, never a moving branch.
The v0.4.0 tag is a lightweight reference; its referenced commit is Verified.

`motd.stage_release` downloads bounded files over HTTPS into a new private
tree, checks independent hashes, exact version/manifest and Bash syntax before
any downloaded code executes. Source-owned checksums alone do not establish
trust. Sources and canonical ancestors must be protected and root-owned;
sticky root-owned parent directories are allowed. Source symlinks, hard links,
oversized files and writable source trees are rejected.

After questions the internal Base review invokes the documented native API:

```sh
bash /protected/source/install.sh --check --source-ref v0.4.0 --root /fixture/root
```

This read-only check verifies owned state and bounded runtime execution of
correctly checksummed managed executables. The complete plan records source
fingerprints and module paths, then checks them again during arming, Base apply
and fresh SSH acknowledgment. Declining writes no target or transaction state.

| Native health | Reviewed action |
| --- | --- |
| Healthy pinned ref/version/payload/command | `check`; no native mutation |
| Clean absent state | `install` |
| Healthy different saved ref | `update` |
| Missing/modified executables or failed runtime | Explicit `repair`, visible in the final plan |
| Invalid/conflicting/unmanaged state or invalid JSON | Blocked; manual review |

A healthy matching ref with unexpected version or executable hashes is not
accepted as a no-op. Repair is authorized by the complete plan's single final
confirmation, not by a hidden menu answer or an invented native flag.

## Ordering and native ownership

Guarded Base and its IPv6 probe run first. Complete Base health and a verified
fresh SSH connection commit Base and remove its old address/path. Only then
does the detached MOTD worker start. Module failure never reopens that commit
or removes retained packages.

The worker receives a private durable verified source copy. In fixtures it
copies only that source to a private run path under the committed target's
`/var/lib`, then runs the unmodified installer in chroot with explicit
`--install`, `--update` or `--repair`, `--source-ref` and `--source-directory`.
The target UTS/network namespaces are protected fixture handles. Mutating
`--root` is deliberately unsupported by the native API. Profiles cannot supply
installer paths, commands, arbitrary sources, refs or environment overrides.

Native state, backups, installation and ordinary rollback remain the MOTD
installer's responsibility. A healthy repeat uses read-only `--check` and
creates no target source staging or managed-file rewrites. Completed modules
verify exact ref/version/hashes and bounded payload and `server-info` execution.
Automatic installation never enables new `PrintLastLog` management; native
updates preserve existing owned settings according to their native lifecycle.

## Durable result and interruption

| Phase | Meaning |
| --- | --- |
| `prepared` | Source/action reviewed; Base remains guarded and uncommitted |
| `queued` | Fresh SSH committed Base; one native worker is queued |
| `running` | Durable intent precedes native mutation |
| `completed` | Native action and pinned final health passed |
| `failed` | Native action/health failed; committed Base is preserved |
| `interrupted` | Dispatch/writer/boot interrupted; mutation is not automatically retried |
| `cancelled` | Base recovered before commit; native writer never started |

`module-active.json` blocks a new Base run while a module is unresolved, including
the gap after Base commit and before execution. The native worker holds the
project lock and the native installer's separate `/var/lib` lock. Repeated SSH
acknowledgment never dispatches the module again.

Base's deadline is disarmed after commit, while owned boot/failure observer
units remain until module termination. The observer stops the whole native
cgroup before acquiring the common lock, records interruption and attempts
read-only native health. It never retries installation, uninstalls uncertain
state, deletes unmanaged files or undoes Base. Terminal observation clears the
reservation and removes the remaining owned units.

An ordinary failed native action can report `manual_attention: false` only if
observed module content/type/owner/mode/regular-file mtime matches the reviewed
originals. The action still failed. Partial/unknown state needs attention;
SIGKILL and power loss always report interruption with attention. Native traps
do not provide an independent power-loss rollback guarantee.

Status includes phase, action, source ref/version, native health, bounded result
tails, reason and `base_policy: preserved`. Private source/journals remain for
diagnosis. Mutation is bounded to 90 seconds, caller health to 40 seconds and
the module unit to 180 seconds with cgroup cleanup.

## Validation and remaining scope

Regressions cover read-only review/decline, independent download pins, source
tampering, stale paths, same-ref hash conflicts, repair, dispatch ordering,
cross-run serialization, healthy repeat, native failure and interruption.
Debian 13 CI uses the unmodified released installer/payload after real
Base/APT/UTS and OpenSSH commit. A read-only proc mount in the owned target lets
the real report observe its UTS hostname and kernel data; cleanup checks the
owned mount identity before unmounting. Scenarios cover successful install and
repeat no-op, native failed-install rollback, killed native child and cancelled
module after Base failure. Failure payloads have explicit fixture-only pins;
the released installer remains unchanged.

VPS/provider routing, package-owned locale/shell aliases, global hooks and a
healthy full reboot remain production acceptance requirements.

Native reference: [v0.4.0 installer contract](https://github.com/RzandAl/debian-server-info-motd/blob/v0.4.0/docs/INSTALLER.md).
