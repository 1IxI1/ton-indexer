# Bounded analytics store prototype (review only)

`schema.sql` is **not deployed**. `store.py` is standalone Python 3 (standard
library); it opens only its caller-chosen local SQLite ledger, never ClickHouse.
`SqlRows` accepts caller-supplied synchronous `insert_json(sql, bytes)` and
`select(sql, named_parameters)` functions (typed rows with integer `revision`).
It does not construct a connection,
parse credentials, enable async INSERT, or print secrets. The tests use memory
rows; no node, archive, ClickHouse, or full backfill is accessed.

## Protocol

1. Use a **single durable owner ledger per dataset/network** (exclusive to this
   producer; keep/back up its SQLite file). Construct `Scope` using the real
   zerostate root **and file hash**, full MC anchor ID (`workchain`, 16-hex shard,
   seqno, root hash, file hash), predecessor as specified below, optional range-end MC ID, metric,
   `calc_version`, and frozen dependency-version mapping. `scope_id` must be
   stable for the logical date/anchor slot across revisions. The stable
   publication key excludes the MC anchor, while each **batch** carries its
   full anchor/provenance in `scope_json`; a corrected daily anchor can replace
   the older publication without losing either source identity.
   A `Scope(kind="address_subset_at_anchor", address_manifest=...)` instead
   keys the **sorted raw wallet addresses (SHA256), full MC anchor and its
   predecessor** into its identity. It accepts 1–256 distinct lowercase
   `workchain:64-hex` addresses. A membership or anchor change is a *different*
   subset, not a revision of the original subset. A subset is never the global
   `snapshot_at_anchor` scope, even if network/dataset/metric/scope_id match.
2. Split a small complete result into 1–256 parts, at most 256 facts per part.
   Existing `Fact` remains a backwards-compatible numeric record. Prefer
   `TypedFact(record_type="numeric_verified", value_decimal="...")` for a
   verified exact signed integer, or `TypedFact(record_type="unresolved",
   status="unknown"|"error"|"unsupported"|"not_present", reason="...")`.
   **Unresolved wire records have no `value_decimal` key at all**, not even
   null or 0. Typed records require 1–16 `SourceID(full BlockID, state_root)`
   entries and may carry string-only provenance. Subset facts must be typed,
   keyed by a listed wallet address, include the subset MC anchor and non-null
   state roots; every listed address must have exactly one fact across parts.
   `part_content` gives
   the canonical payload SHA; declare the **entire immutable expected manifest**
   (including an explicit empty part for a verified zero-result batch), then
   `put_part`. Replaying identical bytes is safe; a differing part fails.
3. `complete` takes independently collected expected and processed **source
   references** (canonical JSON objects with `block` = full BlockID and
   `state_root` = hash or null), and a caller-computed `checks_passed=True`.
   It refuses missing/duplicate sources, failed checks, missing parts or a
   duplicated logical fact key. **Any unresolved fact keeps its batch pending**
   even if `checks_passed=True`; this includes conservative `not_present` until
   independently reviewed absence semantics are represented without a fake
   balance. It writes a completion marker with exact
   part manifest SHA, coverage and checks; after read-back on the configured
   CH path it marks the batch **READY** in SQLite. A 1-nanoTON Supply residual
   must cause `checks_passed=False`; a required but unresolved predecessor
   transition must remain incomplete: successful insertion alone is not a validation.
4. An explicit higher-level finalizer invokes `publish(scope,batch,id)` only
   after validating relevant inputs and CH visibility. SQLite atomically moves
   the per-scope **PUBLISHED** pointer to a strictly higher revision. `approved`
   pins that one publication ID and reads *only its batch*, deduplicating
   identical physical retries by part ID. It fails closed if any fact/marker
   is missing or conflicting; it never inherits deleted keys from a prior
   revision. No materialized view may sum physical inserted rows.

Example integration for Supply: form a stable metric/scope from the coordinator;
pass checked four component/total/residual facts as decimal nanoTON strings,
with the real MC/state/queue provenance; independently enumerate the expected
and processed shard-tip/state roots and auxiliary MC states. Mark ready only
when the native Supply invariant and predecessor transition pass. Construct
other metrics (Gram fees, burned, minted, accounts, per-block tx) as **separate
scopes/checks**; event days must first establish a complete MC+shard frontier,
not infer coverage from the current MC clock. The Supply CLI and manager modules
can call this interface after their computations; no existing indexer paths or
CLI are changed here.

### Scope v1 semantic extension: unknown snapshot predecessor

`mc_predecessor` is still a required field. For **`snapshot_at_anchor` only**, an
unavailable/unexported full predecessor ID may be `None`, encoded as literal JSON
`null`. A supplied predecessor must still be a full masterchain `BlockID`.
`event_range`, `lifetime`, and `address_subset_at_anchor` still require a non-null
full predecessor ID. Never substitute the anchor itself or fabricate seqno/hash
values. Null describes missing exported metadata, not a failed native header/hash
check; retain those check statuses separately. It establishes no continuity or
transition proof and does not satisfy any metric-specific transition requirement.

This additive input extension keeps envelope `schema_version=1`. Existing non-null
scope serialization and keys are byte-for-byte unchanged, including stored ledger
rows; no old ledger rewrite or physical ClickHouse migration is needed because
`scope_json` is a string. Consumers must have this store extension before ingesting
null snapshot predecessors. The Validators mapper records
`mapping=standalone-validators-snapshot-v2` (plus its source SHA256) in dependencies
so newly corrected envelopes have distinct run/scope identities.

### Exact mapping for the Assets pending JSON envelope (pilot only)

For `ton-analytics-assets/AssetFacts.cpp::render_batch_json`:

| Assets JSON | Storage protocol |
| --- | --- |
| `dataset`, `metric`, `scope`, `network`, `zerostate`, `zerostate_file_hash`, `calc_version` | `Scope` fields. Require `scope == "address_subset_at_anchor"`; never map it to global `snapshot_at_anchor`. |
| `mc_full_id`, independently obtained full predecessor ID | Parse strict workchain/shard/seqno/root/file into `Scope.mc_anchor` and `mc_predecessor` (`BlockID`); the envelope itself **does not carry predecessor**. This Assets subset still requires a non-null predecessor; the null extension is for snapshots only. `mc_state_root_hash` is the anchor `SourceID.state_root`, not a replacement for either block hash. Synthetic fixture IDs are placeholders and will fail strict parsing. |
| `observations[].wallet_address` | Exact `Scope.address_manifest` (sort/dedupe/validate raw address; no silent omissions), and one `TypedFact.key` per address. Empty observations are not a ready subset. |
| `observations[].status == "found"` with validated `raw_signed_jetton_balance` | Only after **independent** proof/audit and exact canonical integer validation, make `TypedFact(record_type="numeric_verified", value_decimal=raw_string)`. Do not infer verification merely from the JSON `address_scope_ready` or raw getter output. |
| `status == "unknown"` / `"error"` (including when raw getter returned a non-null string) | `TypedFact(record_type="unresolved", status=..., reason=observation.reason or an explicit nonempty diagnostic)`; omit `value_decimal` entirely. Preserve `reported_status`, `source.tip_manifest_sha256`, audit report digest or SHA256 of the original observation as **string provenance**, not as a verified balance. |
| `status == "not_present"` | Pilot maps to `unresolved/status="not_present"` with explicit absence reason; it cannot make this batch READY. A separately reviewed verified-absence representation is needed to publish mixed found/absent subsets. |
| `source.mc_full_id`, `source.mc_state_root_hash`, `source.wallet_tip_full_id`, `source.wallet_tip_state_root_hash`, `source.master_tip_full_id`, `source.master_tip_state_root_hash`, `source.current_shard_tips[]` | Parse *all* available full block IDs and state roots into deduplicated `SourceID` entries, including anchor and the wallet/master tips. Missing/malformed IDs/roots fail closed. `getter_context_audit` and hashes belong to caller's independent `checks_passed` validation, not a fabricated numeric value. |
| `completion.*` | `readiness_basis="caller_attested_only"`, `writer_committed=false`, `publication_ready=false`, `global_metric_complete=false`, `daily_complete=false` remain as emitted; do not rewrite the producer JSON or interpret its `address_scope_ready` as `Writer.complete`. Derive `expected_sources` from an **independently verified** MC/shard/state manifest, compare actual `processed_sources`, then run caller checks; only afterwards may this subset become locally READY/PUBLISHED (still never global). |

`expected_sources == processed_sources` is necessary but not proof: a producer
can omit a shard from both. The envelope lacks the strict predecessor and an
independently established complete frontier, so **there is no direct automatic
JSON-to-publication path** in this repository.
The per-fact 16-source-ID and per-subset 256-address limits fail closed; a
larger tip manifest or subset needs a separately reviewed bounded extension,
not truncation or silently missing sources.

## Boundaries requiring review before deployment

- ClickHouse MergeTree has neither unique constraints nor cross-table atomicity.
  This implementation relies on **one fenced owner** of the durable SQLite
  ledger for *all* producers to a given dataset/network. A second independent
  ledger, stale worker or CH-writer bypass can race the read-before-write
  conflict checks. Physical CH rows are revalidated on every approval/read,
  but this does not prevent already-served answers being invalidated. A
  production coordinator needs fencing/leader recovery and publication storage
  accessible to the API; local SQLite is **not** a replicated publication API.
  Consequently even a locally PUBLISHED subset is **pilot-only**, never a
  globally safe/API-ready metric.
- Synchronous INSERT acknowledgment is not necessarily visibility on a
  different CH replica/query path. Read-back checks the adapter's configured
  path only; a later/lower-level delayed or reordered replica can expose rows
  after a publication. Configure and verify a consistent replica/read quorum
  and replica health policy (or route reads to one guaranteed path) before
  publication. On absent/conflicting read-back, **do not serve partial data**.
  No live ClickHouse behavior or SQL migration has been tested here.
- The caller, not this storage layer, establishes canonical chain coverage,
  verified state roots, historical config, independent `expected_sources`,
  predecessor/transition checks, and dependency readiness. Equal self-reported
  lists alone do not prove completeness. This prototype does not construct
  cross-scope publications or derived daily series; add a separate publication
  manifest for those.
- Source/hash spelling is lowercase hex; exact values are decimal **strings**
  throughout. Snapshot totals are not additive across days. `MAX_JSON_BYTES`
  caps individual payloads and completion manifests (256 KB); larger covers
  require a bounded manifest-tree extension rather than truncation.

Offline verification: `python3 -m unittest -v test_store.py` in this directory.
TON terminology cross-check: [TON Docs Start here](https://docs.ton.org/llms/start-here/content.md)
(masterchain/shards, account state and transactions). Storage/completion rules
follow `docs/TONSTAT_ANALYTICS_ARCHITECTURE.md` §§2–4 and
`docs/TONSTAT_GRAM_AND_TON_TECHNICAL.md`.
