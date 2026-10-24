# Analytics in the v1.3 indexer

Build with `-DTON_INDEXER_ANALYTICS=ON` (default **OFF**). Runtime remains off
until `--analytics-spool` is supplied. The hook is in the real `IndexScheduler`,
after interfaces/actions and before insertion. It receives the **same**
`ParsedBlockPtr`, raw `mc_block_`, and `cell_db_reader_` produced by the existing
DbScanner/ParseManager. It creates no scanner/parser and performs no MC0 lookup.

## Bounded replay, same executable

```sh
ton-index-clickhouse \
  --db /var/ton-work/db \
  --working-dir /var/tmp/analytics-replay-92976409/work \
  --analytics-spool /var/tmp/analytics-replay-92976409/spool \
  --analytics-only --from 92976409 --to 92976410 \
  --prewarm 50 --max-active-tasks 2 --threads 4
```

Use a new work directory, or one bearing this mode's marker. Work, spool and
NodeDB paths must be absolute/disjoint; output symlinks are rejected. Replay
opens the existing **secondary** scanner path. It never constructs
`InsertManagerClickhouse`, accepts `--ch`/`--force`, reads the production skip
list, or changes normal indexer resume state. Existing trace prewarm semantics
are preserved: preceding blocks warm context but emit no facts outside `from..to`.
Exit 3 means one or more analytics processing/durability failures.

For normal indexing, append `--analytics-spool /absolute/separate/spool` to the
existing command. Legacy insert/retry/ack behavior is preserved on analytics
failure. Pending analytics is recovered with bounded `--analytics-only` replay,
not by re-inserting an already indexed main database block.

## Facts and limits

* Core verifies original bytes, full IDs, raw global ID, state updates and the
  pinned published network pair. Local archive integrity is **not** a signature
  or MC0-to-anchor consensus proof.
* Validators uses `run_verified_mc` on the retained input. Full rosters/positions
  and exact decimal integers are retained. Unestablished election metrics stay
  null, independently of ready config-34/frozen snapshot metrics.
* Flow uses the existing raw fee-augmentation extractor and each raw block's
  execution MC reference. Only verified historical config metadata already seen
  by this pipeline is usable (128 MC entries by default,
  `--analytics-config-history`). Missing context is pending; increase prewarm for
  a new replay. No current-config substitution or transaction-fee approximation.
* Wallet events resolve historical code through the existing reader. With two
  verified complete snapshots, raw predecessor/tip/time checks and independent
  `WalletRawInventory` feed `WalletStage`. No lifetime baseline or closed day is
  invented. NFT initialization candidates remain candidates, with all evidence
  serialized. `--analytics-asset-wallet <address>` optionally selects up to 32
  historical asset-wallet observations from the same snapshot; absent getter
  audits remain explicit unknowns. Supply full-state scans are not run per block.
* Metric days use chain timestamps in UTC. Source/version hashes and full block,
  state and execution-config identities accompany facts.

One serialized analytics actor orders inputs by MC seqno. At most
`--max-active-tasks` full parser results wait; only the immediately previous MC
and its reader remain afterward. Config history retains scalar metadata only.
Caps reject a scope rather than truncating candidates/rosters. Default spool
limits: 1 GiB logical bytes, 100000 anchors, 64 MiB/anchor. Change total limits
with `--analytics-spool-bytes`/`--analytics-spool-entries`.

## Durability and writer handoff

Before extraction, `<seqno>.pending/identity.txt` is fsynced. Successful output
fsyncs `facts.ndjson` and a SHA256 receipt, atomically renames the directory to
`<seqno>.committed`, then fsyncs its parent. **That is the analytics ack boundary**;
it means local spool durability, not store ingestion or metric completeness.
Missing-context facts can be durably committed with null values. Failed
extraction/commit leaves pending intent; `failure.txt` and the conservative
`rescan-required.txt` interval identify replay work. The latter remains a
conservative audit record after recovery. A full spool refuses more facts and
records a bounded rescan interval while normal legacy inserts continue.

Do not delete committed entries to free capacity: they also protect replay
identity. Rotate to a new spool after writer ingestion. Reusing an MC coordinate
with another full ID, or committing different bytes under the same identity,
fails. A process lock excludes concurrent producers. Unreadable/corrupt receipts
are failures, never completed progress. Storage I/O failure is returned/logged
even if writing its diagnostic also fails.

The existing mapper consumes these directories directly:

```sh
python3 ton-analytics/pack_spool.py /absolute/spool/92976409.committed > envelopes.ndjson
# Feed each complete envelope line to the existing ton-analytics-store/cli.py
# ingest with the analytics writer's existing ledger/transport configuration.
```

Check replay exit status, pending/rescan records, full-ID receipts, mapper
validation and writer readback separately. A normal main-DB acknowledgement
does not imply any of those analytics steps completed.

## Tests

Standalone GCC/Clang: `cmake -S ton-analytics-pipeline -B <build>` builds the
durable spool/path/cap/restart/conflict regression. Native build target
`test-ton-analytics-pipeline-native` runs actual processor → domain extractor →
spool on synthetic native cells, plus real IndexScheduler disabled/enabled/error
hooks with pointer/reader identity and legacy acknowledgements. No NodeDB or
ClickHouse is required by these tests; synthetic fixtures do not certify archives.
