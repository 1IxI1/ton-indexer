# September 2026 raw TON flow backfill (opt-in, read-only)

This target is registered **only behind a default-OFF option** in
`ton-index-worker/CMakeLists.txt`, after the shared `ton-analytics`
subdirectory (which registers `ton-analytics-flow`):

```cmake
option(TON_ANALYTICS_MONTH_FLOW "Build standalone read-only month flow producer" OFF)
if(TON_ANALYTICS_MONTH_FLOW)
    add_subdirectory(ton-analytics-month-flow EXCLUDE_FROM_ALL)
endif()
```

Compile explicitly: `cmake --build <build-dir> --target ton-analytics-month-flow -j8`.
The isolated Clang 21 build on pinned TON `afe8bfb` linked successfully after
removing a duplicate CMake configure-input rule; production remains OFF.

After review, use existing directories on disjoint paths (only the secondary
and output workdir are written). `--from` is inclusive **MC seqno**, `--to`
exclusive MC seqno; **not dates**. For the full September V3 coverage, including
the first October MC needed for late September shard blocks:

```sh
<build-dir>/ton-analytics-month-flow/ton-analytics-month-flow \
  --db-root /path/to/node-db --secondary-work-dir /path/to/isolated-secondary \
  --workdir /path/to/isolated-flow-chunks --network mainnet \
  --zerostate-root 17a3a92992aabea785a7a090985a265cd31f323d849da51239737e321fb05569 \
  --zerostate-file 5e994fcf4d425c0a6ce6a792594b7173205f740a39cd56f537defd28b48a0f6e \
  --from 89799586 --to 96135465 --max-mc 64 --max-seconds 300 \
  --max-blocks 256 --max-transactions 100000 --max-aux 128 \
  --max-output-bytes 67108864
```

One **single** secondary scanner and retained CellDB reader per invocation;
each checkpoint chunk processes at most `--max-mc` MCs and commits an immutable
fsync/rename file. The default `--max-chunks 1` retains old behavior;
`--max-chunks N` (up to 65536) keeps that reader open across N consecutive
chunks while observing the total `--max-seconds` wall budget. Repeat identical
invocation to resume after its last committed chunk. No concurrent second
reader is required for this optimization.
`--prefetch N` (default **1**, cap **8**) starts at most N MC
`DbScanner::fetch_seqno` child queries in parallel within the same reader,
like the existing v1.3 IndexScheduler. Extraction, full-ID/BoC/state/frontier
verification and immutable checkpoint commits remain **strictly in MC order**;
an uncertain or missing fetch fails the in-progress chunk. Larger prefetch
holds more lazy state roots in memory; compare its exact chunk bytes against
a `--prefetch 1` run at the same source pin before using it for backfill.
Do not parallelize multiple invocations or change the workdir scope. `flock`
fences concurrent writers. Completed chunk contents, SHA256 receipt chain,
source fingerprint, contiguous interval and exclusive scope are checked at
restart; a partial `chunk.pending`, foreign file, missing/overlapping chunk,
changed source or mismatched pin stops processing. There is **no silent skip**:
failure or deadline leaves the whole in-progress chunk uncommitted, so choose
smaller `--max-mc` if a chunk takes longer than the wall budget.

For **each** adjacent MC, `verify_anchor` checks original BoC SHA256 against
file hash, root hash, raw header, exotic Merkle update, post-state root,
network/MC0 and exact shard tip snapshot. Independent raw predecessor
reachability checks the entire first-inclusion frontier including split/merge
and unchanged tips; missing or duplicate blocks stop the chunk. Every block
resolves its raw execution MC reference through the including MC's ancestry,
loads that historical MC state, verifies its raw BoC/state, and reads config
#8 from **that predecessor**, not the including MC's current config. Flow's
existing `extract` obtains exact ValueFlow.created/burned and fee augmentations
from original BoCs; never uses transaction `total_fees`. Aggregation keys off
raw **source block `gen_utime`** rather than MC inclusion time. v1 lacks burned:
the partial v2 burn sum is retained but burn is **null/unknown** if any v1 block
occurs. Zero-address outgoing transfers are emissions only; delivered and
protocol burn are distinct and delivery remains unknown.

The chunk NDJSON has verified MC identifiers, full-ID/time/config evidence for
each block (no per-transaction dump), per-MC daily integer sums, and a receipt.
All amounts are decimal JSON integers parsed with checked 256-bit arithmetic;
the offline Python audit rechecks overflow. Source fingerprint covers key C++
sources and pinned TON revision, **not** a complete reproducible-build attestation.
Archive-local verification is not MC-signature verification nor a cryptographic
MC0-to-anchor chain proof.

Only after all chunks exist, run this **offline**, preferably on separate disk
space (SQLite temporary inventory can be several GB):

```sh
python3 -B scripts/tonstat-flow-month/audit.py \
  --workdir /path/to/isolated-flow-chunks --from 89799586 --to 96135465 \
  --v3 scripts/tonstat-month/result.json > /path/to/flow-result.ndjson
```

The audit uses an on-disk unique-coordinate inventory across chunks and checks
the V3 day transaction/block counts and each shard segment's first/last full
IDs (including branch changes). V3 is a *source-derived* cross-check, not
native chain proof. Before full range/segment reconciliation, **all days are
unresolved** with a reason, and numeric flow fields are null. A complete day
can have verified gross fees/created/zero-sink sent while burned stays null
(`value_flow_v1_absent`). No output says zero-sink *delivered* is verified.

The V3 scope contains ~6,335,879 MCs, ~6,465,978 Sep-time shard blocks and
112,176,108 transactions; total scanned blocks may include boundary spillovers.
**Measured bounded archive pilots, 20 October 2026:** the first two-MC
September pilot passed (four source blocks, raw gross fees matching the
separately reviewed same-indexer pipeline). Then two sequential checkpoint
chunks covered **128 MC / 363 first-included raw blocks** across the real
September 3 split; both exited 0 and successfully resumed. They took
**25.021 + 22.560 = 47.581 wall seconds**, inclusive of two independent
secondary CellDB opens (~11–12 seconds each); peak RSS ~2.6 GiB. The
post-start portion was still roughly 0.2 seconds/MC on that host.

**Correction:** dividing 128 MC by 47.581 s is **not** a meaningful
per-block throughput estimate: those 47.581 s contain **two independent
CellDB opens/metadata validation passes**. A previous one-MC secondary smoke
already took about 26 s, similar to this 64-MC chunk. The time after a
metadata notice cannot be assumed to be block processing alone; the metadata
pass can still be running. Earlier multi-week estimates from these two runs
were unjustified and should not be used for scheduling.

Measure a substantially larger contiguous range within one open and
instrument acquisition vs raw extraction before estimating the month. A
future single-reader multi-chunk loop can amortize opening without parallel
pressure on the live primary. Do not claim monthly fees/created/burned from
sample fragments or from CH transaction fees. Existing preliminary NDJSON
fragments remain `incomplete`, never numeric daily/monthly totals.

That larger single-open pilot subsequently processed **1024 MC / 2334
included blocks in 39.503 s** (after ~25 s for the 64-MC cold-start
pilot). This demonstrates that the earlier extrapolation was unsound:
processing more than 900 additional MCs cost only ~15 extra wall seconds
on that sample. A continuous one-reader whole-month estimate is therefore
of order **a day**, not weeks, but remains unvalidated across all 6.34m MCs.
Use the new bounded multi-chunk option to measure sustained resume throughput
and reliability before any full-month operational rollout.
