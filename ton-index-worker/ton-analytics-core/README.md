# Read-only MC anchor evidence (producer library, no database or writer)

`verify_anchor` consumes **already loaded** `schema::MasterchainBlockDataState`,
the externally selected **full** MC `BlockIdExt`, and an out-of-band pinned MC0
root **and file** ID. It does not open a DB, look up a tip, publish results, or
attest validator signatures. Its returned `shared_ptr<const AnchorEvidence>`
owns copied IDs, digests, checks, issues and flags; it does not borrow the
scanner result. `verified_local_archive` means these *local archive consistency*
checks passed, **not** that the archive is canonical, signed or cryptographically
linked all the way to the pinned zerostate. `mc_signatures_checked` and
`cryptographic_zerostate_link_checked` are always false.
The pin must equal the known MC0 **root and file** pair for the raw MC
`global_id`: mainnet `-239` or testnet `-3`, fixed from
[`ton.org/global.config.json`](https://ton.org/global.config.json) and
[`ton.org/testnet-global.config.json`](https://ton.org/testnet-global.config.json)
(consulted 16 Oct 2026). `ConfigInfo::extract_config` independently decodes
the MC post-state `OldMcBlocks[0]` root/file, which must equal the same trusted
pair; the same check applies to a supplied previous or auxiliary MC state.
Unknown networks or other genesis eras require an explicitly reviewed identity
update, **not** a caller-provided substitute. This is an identity comparison,
not a proof of consensus or a full MC0-to-anchor chain.

The raw verifier checks the selected MC and every supplied tip/diff block:
handle and BlockData full ID, SHA-256 of **original** block BoC bytes against
`file_hash`, block root representation hash against `root_hash`, BlockInfo
identity, native MerkleUpdate validation, raw `new_hash` against the loaded
post-state cell hash, and TL-B ShardStateUnsplit shard/seqno/global ID/time.
It derives `mainnet` (`-239`) or `testnet` (`-3`) from the *raw MC global ID*;
unknown IDs fail closed. It extracts the *exact* expected full-ID top-tip set
from MC post-state `ShardHashes`, **validates the complete TL-B dictionary and
every leaf** before enumeration, and compares it to the supplied unique
full-ID tips. A seqno-zero tip is enumerated but results in explicit
`incomplete/unsupported_zero_seqno_tip` (not a successfully decoded ordinary
Block). For nonzero tips, it validates each diff entry and its shard
handle's MC inclusion reference, uniqueness, MC presence, and MC post-state
equality. With a **loaded** adjacent previous MC block/state, it validates
that input anew and checks both the raw current predecessor full ID and the
current Merkle update's `old_hash` against the previous post-state root. An
unavailable cell/block/tip is `incomplete`; contradictory raw input is `error`.
`status=verified_local_archive` with `snapshot_integrity_checked=true` certifies
only the loaded snapshot; if no previous anchor was supplied,
`continuity_status=incomplete` and `continuity_reason=adjacent_previous_mc_not_supplied`.
Only `continuity_status=verified_local_archive` permits a caller to claim the
adjacent MC full-ID and old-state link. Count of config #34 can consume a
verified snapshot **without** continuity; delta/event-range completion cannot.

`DbScanner::fetch_seqno` intentionally omits zero-seqno shard tips. The separate
runner can inspect `expected_shard_tips` and `missing_tip` issues and load any
missing **nonzero** tip by full ID for `extra_tips`. Fetching a seqno-zero ID
with `fetch_block_by_id` is **not sufficient**: MC0/shard zerostates need a
separate verifier for their zerostate state and BoC format. Until then this
anchor stays incomplete; never fill a missing tip with zero. A separate
historical MC state is checked with `verify_auxiliary_mc(entry, full_id, pin)`;
its evidence has `Scope::auxiliary_mc_only` and must not be treated as a
complete snapshot or automatically as an ancestor of another MC state.

For state/account/config extraction by Assets, Validators or Wallets, pass the
original `ParsedBlock::cell_db_reader_` as the `reader` lease to
`verify_anchor`. Only a **verified** outcome with this lease has a non-null
`view`; retain `shared_ptr<const MaterializedAnchor>` until synchronous or
asynchronous extraction is done and read from `view->snapshot()` (it contains
copies of the supplied `td::Ref`s **and** all separately loaded tips). Do not
save a bare `const schema::BlockDataState&`, raw cell or `CellSlice` after the
view is released. The reader is *held*, not independently opened. An outcome
without a reader still offers persistent **cell-free evidence**, but not a view
for later lazy-cell reads. Consumers must independently prove that their
snapshot account lookup, historical config, transaction replay and downstream
dataset-specific coverage are correct; this library never marks those ready.

Known non-proofs: MC signatures, canonical chain from MC0, full scan of the
archive for **diff exhaustiveness**, shard split/merge ancestry, source account
membership, publication/CH completion, wallet lifetime/UTC day coverage, and
agreement between a selected anchor and any separately loaded election state.
`diff_handle_inclusion_checked` is only the indexer's handle reference;
`diff_exhaustiveness_checked` remains false. A separate canonical frontier walk
is required before publishing event-range completeness.

## Local tests / integration gate

`AnchorEvidence.test.cpp` runs synthetic positive and fail-closed checks of
the **same** digest/set/continuity functions called by the native verifier:
file/root/new-state hash mutations; zero-seqno omission; duplicate/extra tips
and diff IDs; cross-network/arbitrary MC0 pins; MC absence from diff; global-ID,
state-hash, predecessor full-ID
and adjacent-state mutations. These are relationship fixtures, **not** an
archive-backed positive Merkle/BoC integration test. `NativeEntry.test.cpp`
covers missing MC/handle, bad pin and a malformed nonempty `ShardHashes` TL-B
cell fail-closed entry paths when the fork is
buildable. No test opens NodeDB or writes ClickHouse.

The local `CMakeLists.txt` provides `ton-analytics-core`,
`test-ton-analytics-core` and `test-ton-analytics-core-native`. The indexer
root CMake is intentionally untouched. On this checkout (16 Oct 2026), a
native build is **not possible**: even when configuring with Homebrew OpenSSL,
`external/ton/third-party/{abseil-cpp,crc32c,ngtcp2,tl-parser,libbacktrace}`
are unpopulated/missing CMakeLists.txt or source. The secondary-open/GC port
also needs review before *any* NodeDB run. The synthetic binary was compiled
and passed against the **separately prebuilt `ton/` library**; native files
were syntax-checked against the nested fork using temporary generated TL-B
headers and the separate `ton/` generated fallback. This is **not** a native
fork link test: that fallback's ABI/API differs (`ShardConfig` differs), so no
integration or live archive success is claimed.

Proposed adoption: (1) restore/review nested TON dependencies and build local
targets; run synthetic + native tests and add real MC block/post-state fixture
including a tested *separate* zerostate path for any zero-seqno tip; (2) add a
separate secondary-only runner which pins MC0 and supplies missing **nonzero**
full-ID tips and previous/auxiliary MC
states; independently verify diff ancestry; (3) hand `view` plus immutable
evidence to Assets/Validators/Wallets, removing their caller-attested booleans
**only after** comparing their current checks and domain-specific readiness;
(4) integrate scheduler/writer/publication separately after safety review.
Supply CLI has a similar raw BoC/Merkle validation path but has **not** been
refactored to reuse this library.

TON Docs consulted: [Start here](https://docs.ton.org/llms/start-here/content.md)
and [Merkle updates](https://docs.ton.org/llms/foundations/serialization/merkle-update/content.md).
