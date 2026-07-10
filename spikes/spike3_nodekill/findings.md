# Spike 3 findings: atomic erasure surviving a node kill

Status: NOT RUN YET (needs Docker Desktop running)

Run `./run.sh` (commit-then-kill, reliable) or `./run.sh midflight` (harder race).

## Result

- [ ] PASS (committed erasure state survives a node kill from a surviving replica, reproducibly
           across several runs; killed node catches up on restart)
- [ ] FAIL (killed-node timing unreproducible, or committed state ever inconsistent after a kill)

## Record

| Field | Value |
|-------|-------|
| variant | commit-then-kill / midflight |
| runs survived | e.g. 3/3 |
| erase commit latency | |
| catch-up on restart worked | |
| CRDB image tag used | |

## Consequence

- PASS -> resilience beat confirmed (the beat Rob Reid cares about). Proceed.
- Mid-flight timing unreproducible -> NOT a concept change. Use the honest commit-then-kill
  variant: commit the erasure first, then kill a node, show committed state surviving from a
  survivor and the killed node catching up on restart. Fully honest, slightly less dramatic.
- Committed state inconsistent after a kill -> a serious, surprising result; investigate the
  cluster before trusting it (do not proceed).

The video's node-kill segment records against this LOCAL cluster (real Raft), disclosed as local
because the managed cloud cluster's nodes cannot be killed by us.
