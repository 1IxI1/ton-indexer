# Raw first-inclusion Gram flow extractor (opt-in)

`extract(schema::MasterchainBlockDataState, AppliedGlobalVersion)` consumes **only** `shard_blocks_diff_`,
requires a single first MC entry, and returns immutable-in-practice in-memory block
and per-out-message observations or throws. No NodeDB reads, ClickHouse writes,
state snapshots, network credentials, or aggregate daily publication.

The block fact keeps exact decimal nanoTON for the two independent gross-fee
augmentations, `created`, and the v2 `burned` total. For v1, burned is null with
an explicit status (its TL-B field does not exist). Fee-burn/blackhole breakdown
is **always unknown** here: proving it needs predecessor MC config #5 and the
separate MC rounding calls plus independent delivery evidence. Never subtract
the separate `0:000...000` send amount from supply or call it protocol burn.
The minted.grams diagnostic is not added to created. The outgoing key is full
source block ID + tx account/LT/hash + 15-bit out-message index; duplicate
message hashes do not collapse different sends. Delivery is unresolved.
For anycast destinations, both the encoded address and the effective rewritten
address must be `0:0`; non-256-bit destinations that cannot be normalized fail
the batch instead of being assumed not to match.

The two clocks are `BlockInfo.gen_utime` and first MC inclusion's
`BlockInfo.gen_utime`. The caller must bind a network/zerostate, prove ancestry
and complete MC/shard coverage including delayed shards and split/merge, persist
idempotently by full block ID, and close days only with a proven shard frontier.
File hash comes from the trusted block handle; it is *not* independently derived
from serialized raw bytes by this module. Bounds are adjustable with `Limits`;
a limit exceeded invalidates the whole batch. This is an extraction contract,
not a ready-to-publish daily dataset.

**Required historical input:** the callback returns config #8 `global_version`
from the **execution predecessor MC state for each individual block** (including
shard blocks that may predate their MC inclusion). The extractor rejects a
missing resolver, `nullopt`, or a version newer than this TON build supports;
it records each applied version in its block fact. The native
`Aug_InMsgDescr(global_version)` uses legacy `extra_flags` as IHR for pre-v12
messages; `aug_InMsgDescrDefault` incorrectly uses `SUPPORTED_VERSION=16` for
historical blocks. A post-state `MasterchainBlockDataState::config_` or a
single version for the whole diff is not a valid substitute. The callback's
historical source/proof must be preserved by the integrating caller.

To opt in, add this directory to a compatible indexer CMake build and build
`test-ton-analytics-flow`. Tests exercise synthetic 0/1 tx counting, two
index-distinct sink sends, missing version/root rejection, and native pre-v12
IHR augmentation arithmetic. These are **not** full raw block/transaction BoC
fixtures; live historical raw BoC/zero-sink tests remain necessary before rollout.
