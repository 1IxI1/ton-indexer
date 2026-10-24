-- REVIEW ONLY: never applied by this module. Create database/user separately.
-- Append-only, deliberately NOT ReplacingMergeTree or SummingMergeTree.
-- Duplicate physical INSERTs are normal; consumers must select one approved batch
-- and collapse identical retries by part_id, never sum/count physical rows.
CREATE TABLE IF NOT EXISTS ton_analytics.analytic_parts
(
    scope_key FixedString(64),           -- SHA256 stable logical scope (anchor excluded)
    network LowCardinality(String),
    zerostate FixedString(64),
    zerostate_file_hash FixedString(64),
    dataset LowCardinality(String),
    metric LowCardinality(String),
    calc_version String,
    dependencies_sha256 FixedString(64),
    scope_kind LowCardinality(String),
    scope_id String,
    scope_json String,                  -- batch's full MC/predecessor/end IDs and hashes
    address_manifest_sha256 Nullable(FixedString(64)), -- subset only; null for global
    batch_id String,
    revision UInt64,                   -- assigned by coordinator, not arrival time
    part_id String,
    content_sha256 FixedString(64),
    facts_json String                  -- bounded canonical array; typed numeric_verified
                                       -- (exact decimal) OR unresolved (status/reason,
                                       -- NO numeric value), with full source IDs
)
ENGINE = MergeTree
ORDER BY (scope_key, batch_id, part_id);

CREATE TABLE IF NOT EXISTS ton_analytics.analytic_completions
(
    scope_key FixedString(64),
    batch_id String,
    revision UInt64,
    completion_sha256 FixedString(64),
    completion_json String              -- exact part manifest, coverage, checks
)
ENGINE = MergeTree
ORDER BY (scope_key, batch_id);

-- These tables are NOT the publication authority. The single-writer durable
-- SQLite ledger in store.py supplies uniqueness/CAS and the published pointer.
-- Deployment must specify a consistent read path, synchronous inserts and
-- replica visibility policy before enabling publication.
