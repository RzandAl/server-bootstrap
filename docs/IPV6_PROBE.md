# Temporary IPv6 probe

`0.6.0-dev` checks a selected IPv6 candidate under the independent recovery
supervisor before permanent files or the live network transition. The bootstrap
wizard remains read-only and displays the planned destinations. Production
`--apply` remains unavailable while Base and module wiring is unfinished.

## Success policy

The contract contains a canonical candidate CIDR, an in-prefix or link-local
gateway, and typed external IPv6 TCP destinations. It must match the planned
permanent IPv6 address and default gateway. Off-prefix global gateways require
provider-specific support and are rejected by this implementation.

| Check | Required evidence |
| --- | --- |
| Address | Exact candidate, completed DAD, no `tentative` or `dadfailed` |
| Routing | Marked lookup selects the owned table, selected interface and proposed gateway |
| Gateway | NDP resolves the gateway to a usable neighbor state and Ethernet address |
| External path | At least one TCP connection succeeds from the exact candidate source with the owned packet mark |
| Cleanup | All owned temporary operations are undone and the original network inventory remains present |

The standard destinations are centralized in `bootstrap.py`:

| Service | IPv6 address | TCP port |
| --- | --- | --- |
| Cloudflare | `2606:4700:4700::1111` | `443` |
| Quad9 DNS | `2620:fe::10` | `53` |

These are TCP handshakes only: no DNS query, application payload, TLS assertion,
or DNS-service health claim. Two destinations reduce dependence on one service;
both failures stop application without silently disabling IPv6. Gateway Echo
replies are optional; NDP plus the marked external path establish the check.
DAD is bounded to eight seconds and each connection to four seconds.

## Temporary ownership

Preparation records the link identity, original addresses/routes and diagnostic
neighbor inventory without changing live networking. It selects an unused
numeric routing table, rule priority and non-conflicting packet mark from a
reserved pool. If the allocation or reviewed inventory changes before the first
mutation, the worker refuses the stale plan.

An absent candidate is added with permanent valid lifetime, `preferred_lft 0`
and `noprefixroute`. This keeps it out of ordinary automatic source selection
and avoids an added connected-prefix route in the main table. DAD remains
enabled. An existing identical regular address is reused without changing
lifetimes or flags and is never owned by the probe.

The temporary table contains a direct gateway host route and its default route,
both with the candidate as their explicit preferred source. This avoids an old
preferred address appearing in the kernel lookup for a new deprecated candidate.
The temporary rule requires both the candidate `/128` source and the owned mark.
Each TCP socket explicitly binds the candidate, interface and mark; an older
working address or the ordinary default route cannot satisfy the contract.
Existing main routes/rules are not replaced, flushed or restarted. The journal
does not own the kernel neighbor cache.

Every addition has durable intent before its `ip` command and a read-back check.
The private checksummed `ipv6-probe.json` records exact objects, ownership,
operation phases and observed results. Cleanup removes the rule, default route,
gateway route, and finally an owned address. It preserves reused addresses,
unrelated additions, and externally edited objects.

Cleanup must finish before permanent application. A passed probe is terminal
for its temporary ownership: late rollback cannot delete a subsequently added
permanent candidate address using the old probe identity. Application and SSH
acknowledgment verify the matching completed and cleaned result again.

## Interruption and recovery

Only an armed detached fixture worker can run this probe. It checks the active
timer and deadlines again after probing. Worker failure triggers independent
recovery; deadline recovery stops its entire cgroup, including a blocked TCP
child, before acquiring the shared transaction lock.

Recovery attempts probe cleanup, file restoration and network restoration even
if one participant fails. An external edit or changed interface identity is
preserved and leaves recovery incomplete, retaining private state and blocking
another run. After a changed manager generation, boot recovery expires the old
probe journal without replaying obsolete kernel identifiers.

## Verified scope and remaining work

Regressions cover read-only planning, strict input, identifier collisions, source
and mark mismatches, DAD/route/NDP failures, one successful destination, existing
address reuse, durable crash intent, preserved external edits, boot expiration,
and cached-evidence/permanent-candidate checks.

Disposable Debian 13 CI adds real router and external network namespaces. It
checks link-local/global gateways with fresh/reused candidates, duplicate
address detection, a gateway that drops Echo, a working old address with a
blocked candidate, worker `SIGKILL` while probing, and a committed run that
late recovery cannot undo. Received TCP peers verify the actual source address.
Fixture-only nftables rules and test listeners exist inside the disposable
container; no host ports are published.

These tests establish the owned kernel behavior in that environment. They do
not establish a particular VPS provider's routing, external service availability,
arbitrary package-hook effects, or healthy reboot after production Base. Those remain release
acceptance checks.

Relevant primary documentation:

- [Debian 13 ip-address](https://manpages.debian.org/trixie/iproute2/ip-address.8.en.html)
- [Debian 13 ip-rule](https://manpages.debian.org/trixie/iproute2/ip-rule.8.en.html)
- [Cloudflare resolver addresses](https://developers.cloudflare.com/1.1.1.1/ip-addresses/)
- [Quad9 service addresses](https://quad9.net/service/service-addresses-and-features/)
