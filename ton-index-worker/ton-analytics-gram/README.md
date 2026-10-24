# Bounded native supply audit (offline pilot)

This executable is **not** an analytics writer or a network client. For a live
primary NodeDB it opens `DbScanner(dbs_secondary)` with a required, separate,
pre-existing `--secondary-working-dir`. RocksDB writes secondary metadata
**only there**, never into the primary DB; it reads 2–10 consecutive
non-genesis masterchain anchors and emits one NDJSON row per adjacent pair.

```sh
ton-analytics-gram --network mainnet --db-root /path/to/existing/node-db \
  --secondary-working-dir /separate/pre-existing/ton-gram-secondary \
  --from 98654748 --to 98654749
```

**STOP gate (16 October 2026): do not run on any archive yet.** Original TON
commit `0004f60d45e8ebc941a79e99d5b3c70efc9bde12` lacks indexer-specific
secondary APIs. An integration branch `89aad13ba5eafbacc878662332dbfb035c23039f`
restores the surface, but it is not pinned in the parent gitlink, and its
secondary/GC safety has not been verified. RocksDB `OpenForReadOnly` directly
on a **live** primary is undefined behavior: do not replace `dbs_secondary`
with `dbs_readonly` or a writable primary open. The CLI requires both explicit
existing directories; it rejects secondary symlinks, overlap in either
direction, and symlink paths that could point into primary. This CLI-side
preflight is not an atomic race-proof filesystem sandbox: also require the
TON RootDb open-boundary guard and verified secondary/GC behavior before any
archive pilot. No directory is created by the CLI.

For each anchor the CLI checks the full MC ID, SHA-256 of the **original block
BoC bytes** against `file_hash`, block-root hash, state-update post-state hash,
typed state identity/root, and the exact set of current shard
tips in the MC state. Since `DbScanner::fetch_seqno` omits seqno-zero shard
tips, those must be loaded explicitly by **full** ID, including their raw
block and state roots; if unavailable, the pair fails closed. Auxiliary MC
states used by `processed_upto` also come through `fetch_block_by_id` and are
checked against the requested full ID and raw block/state update. No
intermediate shard states are included in a snapshot. Every first-included
intermediate block in `shard_blocks_diff_` still gets the **same** block BoC
hash, raw `state_update.new_hash`, typed state/root/ID and global-ID checks
before its `ValueFlow.created` is used. Each successor raw MC block header
must name the exact previous MC full ID (including both hashes), *in addition*
to the historical MC state dictionary ID and `state_update.old_hash` checks.
A raw-predecessor mutation fixture must rehash/rekey the successor block's
full ID consistently; otherwise it only exercises the *earlier* BoC hash guard.

`calculate_global_balance_at_anchor` supplies the four independent monetary
components, total and MC `ValueFlow.burned`. The created amount is computed
separately from **previous** MC config #14 following TON native
`compare_global_balance`: masterchain block fee + for each new top shard,
`(basechain fee >> shard_prefix_length) * new_blocks`. `new_blocks` is the tip
seqno difference from the matching predecessor (after merge: the maximum of
the two child seqnos; after split: parent seqno; new workchain: zero). This
counts **all** newly included blocks, not just tip changes. `shard_blocks_diff_`
contains the first-included blocks when available, but its size alone is not
the creation multiplier across splits/merges. The CLI checks its **full block
IDs**, block-root hashes and `ValueFlow.created.grams` independently against
the config-derived amount and expected new-block count. The exact signed integer
residual is `next.total - previous.total - created + next.burned`. A nonzero
residual is `invariant_mismatch`, never `verified`.

NDJSON `mc`, `previous_mc` and shard-tip `id` use the same `BlockID` encoding
as `ton-analytics-store/store.py`: signed 32-bit workchain, **unsigned 64-bit
shard as exactly 16 lowercase hex digits**, unsigned seqno, and 64 lowercase
hex digits for each root/file hash. Post-state root hashes are lowercase hex.
TON's `Bits256::to_hex()` produces uppercase, so lowering is explicit; old
decimal-shard/uppercase-hash NDJSON must not be fed to the store without
lossless conversion. These are standalone audit rows, **not** store batches.

All monetary values are JSON **decimal nTon strings**, including negative
residuals; timestamps are measured durations in milliseconds, not estimated
wall-clock throughput. Provenance includes full MC IDs (workchain, shard,
seqno, root hash, file hash), post-state root hashes, shard tip IDs/root hashes,
network/global ID, `source:node_db_secondary` and `mc_signatures_checked:false` (this CLI does not validate
consensus signatures). On any failure, emit `status:error` with a reason and
exit nonzero. A verified pair is a local archive audit, **not** a complete UTC
day or published mainnet supply history.

Build only after the TON integration revision passes its STOP gate:

```sh
cmake --build /path/to/isolated/build --target ton-analytics-gram test-ton-analytics-gram
ctest --test-dir /path/to/isolated/build/ton-index-worker/ton-analytics-gram --output-on-failure
```

`test.cpp` checks known SHA-256 bytes/mutation/empty rejection, 64-bit shard
hex boundaries, uppercase-to-lowercase conversion, wrong/duplicate/missing
raw predecessors and secondary path disjointness (same/nested/ancestor,
missing directory, symlink and symlink parent). No synthetic TON CellDB fixture for a corrupt intermediate
`state_update` or valid-header/wrong-`file_hash` was built: after the STOP gate,
use an isolated mock RootDb/fixture with one intermediate shard block and
mutate (a) only its post-state root/new hash, (b) only BoC bytes while leaving
`BlockData::block_id()` unchanged, and (c) successor raw MC `prev_ref` hashes
while leaving its state old-MC dictionary untouched. Each must emit only
`status:error` and exit nonzero. Test positive two-anchor behavior on an
isolated archive copy **only after** secondary/GC safety review, never the
running production primary during this task.
