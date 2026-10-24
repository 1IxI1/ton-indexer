# Raw masterchain protocol-burn evidence (opt-in, no CellDB state)

**Not registered by default.** Chief can add this hook to
`ton-index-worker/CMakeLists.txt` *after* `tondb-scanner`:

```cmake
option(TON_ANALYTICS_MC_BURN "Build standalone read-only archived MC burn reader" OFF)
if(TON_ANALYTICS_MC_BURN)
    add_subdirectory(ton-analytics-mc-burn EXCLUDE_FROM_ALL)
endif()
```

Then explicitly build target `ton-analytics-mc-burn` on pinned external TON
`afe8bfbba3a9a647d455504718bebd0303dd539b`. No live indexer/scheduler
changes, CH writes or NodeDB writes. The sources were manually compiled and
linked on the isolated pinned TON tree using existing compile/link commands;
the native in-memory fixture passed. The root target hook is not yet registered.
No archive or NodeDB reader has run: leave archive use pending the chief's
approval. The scanner additive
`fetch_archived_block_boc(handle)` delegates to `RootDb::get_block_data`,
never `get_block_state_root`; original `fetch_seqno` stays untouched. Use one
`dbs_secondary` scanner per process; secondary metadata and output paths must
be disjoint from the NodeDB and each other. Only these two side directories
can be written.

## Derivation / exact meaning

Pinned native `external/ton/validator/global-balance-calculator.cpp:477–485`
reads the **current MC Block.ValueFlow.burned.grams** into
`last_mc_block_burned`; at `:501–539`, the global-balance transition computes
`previous.global_balance + funds_created(config #14, shard-tip advances) -
next.last_mc_block_burned`. Accordingly, summing **every** September MC block
`burned.grams` is an independent candidate for September protocol-burned GRAM
under **MC inclusion time**, not a sum of shard-event-time ValueFlow fields,
transaction `total_fees`, or a Supply snapshot delta. Pinned
`crypto/block/block.cpp:1536–1552` and
`ton-analytics-flow/Extractor.cpp:207–221` show v1 has **no burned field**;
v1 is `null` and prevents publication, never treated as zero. The monthly
Supply increase (`+17201843128410179` nanoton from independently verified
MC89799585→MC96135400 post-states) is **not** used to infer burned.

Inputs: complete existing CH V3 `scripts/tonstat-month/result.json` and its
31 exact UTC midnight full-ID predecessor/successor anchors in
`scripts/tonstat-month/anchors.json`. Freeze locally (no network):

```sh
python3 -B scripts/tonstat-mc-burn/prepare.py \
  --anchors scripts/tonstat-month/anchors.json \
  --v3 scripts/tonstat-month/result.json --output /separate/pins.txt
```

Only after separate approval and with an idle reader/build slot, an example
**bounded 1024-MC pilot** (do not run as part of build verification):

```sh
<build>/ton-analytics-mc-burn/ton-analytics-mc-burn \
  --db-root /read-only/node-db --secondary-work-dir /separate/secondary \
  --workdir /separate/mc-burn-pilot --pins /separate/pins.txt \
  --network mainnet \
  --zerostate-root 17a3a92992aabea785a7a090985a265cd31f323d849da51239737e321fb05569 \
  --zerostate-file 5e994fcf4d425c0a6ce6a792594b7173205f740a39cd56f537defd28b48a0f6e \
  --from 89799586 --to 89800610 --max-mc 128 --max-chunks 8 \
  --max-seconds 300 --max-rss-mib 4096 --max-output-bytes 16777216 \
  --max-nofile 1048576
```

`--to` is **exclusive**; the whole month is `[89799586,96135401)` and
MC96135401 (October 1 00:00) is excluded. The previous MC89799585 is read
as an uncounted anchor. A pilot remains `pending`; the offline verifier will
not output any daily/monthly numeric total until the whole exact month is
covered **and** independent created/Supply reconciliation is implemented.
Run `--from 89799586 --to 96135401` using a **different empty workdir**
for the eventual full backfill. Keep all arguments (including `--max-mc`)
unchanged for restart; `--max-chunks` can be raised while reusing the single
secondary reader within a bounded run. Each immutable fsynced+renamed chunk
has all original full IDs, raw MC gen_utime, exact decimal burn or null, and
Merkle update old/new hashes; its receipt SHA256 chains to the previous chunk.
Partial `chunk.pending`, corrupt/foreign/gapped files, altered pins/source,
or changed TON revision hard-fail. A killed in-progress chunk is **not**
automatically deleted or skipped. Output cap per chunk 16 MiB by default;
RSS samples and process NOFILE soft-cap are enforced, alongside wall alarm.
The first 1024-MC archive pilot stopped after a valid 128-MC checkpoint:
`--max-nofile 768` exhausted the archive's descriptors and the secondary
process failed; production services remained active. This target now requires
at least 65536 descriptors and defaults to the native-reader 1048576 limit.
Among the first 128 MC, **16 v1 ValueFlow** records have burned `null`, not
zero. Do not resume the failed pilot after the source fingerprint changed:
use fresh secondary and workdir for corrected-binary tests.

After full coverage, offline-only:

```sh
python3 -B scripts/tonstat-mc-burn/audit.py \
  --workdir /separate/mc-burn-full --pins /separate/pins.txt \
  --anchors scripts/tonstat-month/anchors.json \
  --v3 scripts/tonstat-month/result.json > /separate/audit.json
```

The audit verifies all 31 boundary full IDs, CH V3 30 daily MC counts and
seqno intervals, complete gap-free 6,335,815-MC coverage, no duplicates,
raw full-ID predecessor and Merkle old/new continuity (as recorded by the
native producer), chunk receipt chain, exact UTC day assignment, strict
256-bit addition and exclusion of October MC. A missing MC, unknown
ValueFlow format, v1 null, revised boundary, bad hash/receipt, partial run or
arithmetic overflow yields **`pending` with numeric totals null** and exit 2.
Even after a complete raw closure, the public audit result stays
`pending_independent_supply_reconciliation` with numeric totals null: there
is presently no independent month-long created/config #14 audit to close the
native Supply equation. Its internal raw sum is exercised by synthetic tests,
but deliberately not exposed as a publishable figure or a CLI escape hatch.
CH V3 is source-derived comparison, not a validator-signature proof.

The native reader verifies each original BoC's actual SHA256 against full-ID
file hash, representation root hash, decoded network `global_id=-239`, MC
shard/seqno and full-ID previous header, plus Merkle update exotic type and
adjacent new/old hashes. It does **not** read MC state roots, prove network
signatures or certify historical state reconstruction. MC0 root/file is
explicitly pinned against published mainnet values, but without MC states
the raw `global_id` + archival full-ID chain do not prove MC0 ancestry. Do
not label this as a native full-archive Supply attestation or publish a
monthly total without exhaustive coverage and independent Supply reconciliation.

Performance pilot should report startup vs warmed per-MC BoC read/parse
latency, wall time, peak RSS, open descriptors, output bytes, v1 count and
checkpoint resume behavior. The prior month-flow 1024-MC/39.503s and
11264-MC/267s runs loaded CellDB/shards; they are *not* measurements of this
MC-only reader. Do not extrapolate a whole-month runtime without its own
bounded pilot. Offline synthetic tests:
`python3 -B -m unittest discover -s scripts/tonstat-mc-burn -p 'test_*.py'`.
The opt-in native fixture `ton-analytics-mc-burn-native-test /separate/pins.txt`
tests native SHA/root/network, v1 null, v2 exact burned, unknown constructor,
and parsing all 31 reviewed pins entirely in memory; it does not open NodeDB
or replace a bounded archive pilot.
