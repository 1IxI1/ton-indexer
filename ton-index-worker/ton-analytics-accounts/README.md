# Accounts (existing addresses) — extraction-only prototype

`accounts_total = uninit + active + frozen`; `nonexist` is **not** counted.
Counts are for the post-state of one fully identified MC anchor (including its
MC account dictionary and exactly the top shard dictionaries in that MC state),
not the number of addresses ever observed. `ShardAccounts`' root augmentation
contains **balance**, never a count. The implementation never uses it as one.

## Safe first run

```sh
cmake -S ton-indexer/ton-index-worker/ton-analytics-accounts -B <separate-build-dir> \
  -DCMAKE_CXX_COMPILER=<C++20-compiler>
cmake --build <separate-build-dir>
ctest --test-dir <separate-build-dir> --output-on-failure
```

The independent fixture is the first test; it does not contact a node or
database. `scan_snapshot(input, network, zerostate, limit)` is a read-only,
hard-entry-bounded sample, **incomplete** by default. It refuses missing tip
IDs, hash mismatches and malformed account records (no `continue` on parse
error). A full baseline requires **separate operational approval** to call
`scan_snapshot(..., limit, true)` with a sufficiently high explicit budget;
exceeding the budget still returns incomplete. Do not schedule such a run now.
For accuracy the MC-state shard-config tip set must equal the fetched tip IDs,
and every raw block state-update new hash must equal its supplied post-state
root. A cell missing during traversal throws and never publishes a count.

`decode_step` authenticates raw BoC bytes by SHA-256 file hash and deserializes
the root, checks `BlockInfo` workchain/shard/seqno and the state-update hashes.
For a normal shard block its **old** state hash must equal the exact full-ID
predecessor's post-state hash (also enforced for MC). A split/merge is **pending**:
the transform is not proved by simple hash equality, and this module currently
has no split/merge state transformation verifier. `Counter` independently rejects
split/merge even if a caller sets verification flags. Every `AccountBlock` must
link its old/new account hashes to its first/last transaction, and every tx
inside it must link prior LT, tx hash and account-state hash. Across blocks,
`Counter` validates the same triple plus status against the last touched tx;
for the **first touched tx** it requires a per-address, root-authenticated
baseline `AccountWitness` (membership or verified absence). Neither the current
NodeDB adapter nor a count-only checkpoint produces these witnesses yet:
`decode_step` leaves `baseline_witnesses_verified=false`, so it **cannot**
advance a globally complete count, even if all other checks pass.

Delta parsing and model processing have explicit default ceilings of 256 new
blocks, 100,000 transactions, 100,000 tracked account witnesses and 16 MiB
per raw block BoC; snapshot loading also caps the tip set at 1,024 entries.
Exceeding a ceiling fails, never truncates-and-completes.
Repeated tips are not new events. Failed/pending steps leave the checkpoint
unchanged; a bounded *snapshot sample* never becomes a baseline.

**Integration API needed:** the scheduler must provide a read-only
`schema::MasterchainBlockDataState` for an exact anchor/contiguous predecessor;
pass verified `network` and 64-hex zerostate identity (not an inferred name),
explicit scan budget/approval, and persist the returned full MC ID, MC state
hash, each tip ID + post-state hash, count components, algorithm/version and
completion evidence in a dedicated dataset. The scheduler must NOT use
`ParsedBlock.account_states_` (that parser can log-and-skip missing cells).
To enable delta completion, provide an authenticated previous-anchor account
lookup (including absence, last tx LT/hash and account cell hash), and a
split/merge old-state transform verifier if such transitions are encountered.
Do not flip the two verification booleans without these witnesses.
Storage/checkpointing/publication and the authorization mechanism are deliberately
out of scope. The model has no CH writer, no archive backfill, no network I/O.
Delta snapshots require continuous first-included coverage from the checkpoint;
periodic independent full-state reconciliation at the same anchor is required
before treating long-running results as authoritative. Cross-chain canonical
selection/rollback and externally attested NodeDB trust are also integration
requirements, not supplied by this library.

Primary source references: TON `crypto/block/block.tlb` (`account_none$0`,
`AccountState`, `AccountStatus`, `ShardAccounts`, `Transaction`), TON
`crypto/block/block.h` (`unpack_block_prev_blk_ext`), and indexer
`tondb-scanner/src/DbScanner.cpp` (post-state tips and first-included diff).
See TON Docs `/llms/foundations/status/content.md` and
`/llms/start-here/content.md`. No mainnet full snapshot has been attempted.
