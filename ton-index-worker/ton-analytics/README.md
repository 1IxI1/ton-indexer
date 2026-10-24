# Analytics-only native indexer

`ton-analytics` processes actual archived MC anchors and first-included blocks.
It opens **only `DbScanner(dbs_secondary)`**, retains its `CellDbReader`, and writes
versioned NDJSON to its own local workdir. It never starts `IndexScheduler`, uses
the main indexer's block-skip logic, connects to ClickHouse, or writes main tables.

## Build integration

The root registers Core and the runner after `tondb-scanner`, as explicit targets:

```cmake
add_subdirectory(ton-analytics-core EXCLUDE_FROM_ALL)
add_subdirectory(ton-analytics EXCLUDE_FROM_ALL)
```

Then build `ton-analytics` and `test-ton-analytics-runner`. The local CMake adds
Core and Flow subdirectories if their targets do not already exist.
It links `ton-analytics-core`, `ton-analytics-flow`, `ton-analytics-progress`, its own
`ton-analytics-runner-stages`, `tondb-scanner`, and `validator`; generated
`tlb_generate_tokens` and the normal TON generated TL/TL-B targets are required.
The stage library compiles the existing Validators native Core bridge,
snapshot/election/stage and renderer, Wallets event extractor, and Assets NFT candidate extractor **without
their CLI mains**. It does not modify those modules or bypass their CLI guards.

Requires C++20, Boost Multiprecision headers, the indexer's TON secondary/GC patches and the
`calculate_global_balance_at_anchor` API (the coordinated `afe8bfb` TON pin).
Native Linux links of `ton-analytics`, `ton-analytics-gram`, and the scanner library
were verified on 2026-10-16 with Clang 21.1.8 in the isolated analytics build.
Core, runner resume/spool, and Gram tests passed there. Archive runtime validation
is a separate step; those build/test checks do not open a NodeDB.

The runner's typed Accounts sample adapter is guarded by the default-OFF CMake
option `TON_ANALYTICS_WITH_ACCOUNTS`; enable it to add
and link `ton-analytics-accounts-native`. Without it, a nonzero sample request
fails preflight before opening any NodeDB. The default Linux link verification
does not exercise that optional adapter.

Standalone offline checks need no TON library or NodeDB:

```sh
cmake -S ton-indexer/ton-index-worker/ton-analytics -B /absolute/local/test-build -G Ninja
cmake --build /absolute/local/test-build -j2
ctest --test-dir /absolute/local/test-build --output-on-failure
```

Standalone CMake builds only the offline test executable, not a fake indexer.
Tests exercise real filesystem commits, restart, interrupted staging, corruption,
scope collisions, duplicate block coordinates, failed extraction without progress,
and the same frontier reachability routine used by the native runner. Python tests
also pass generated envelopes through the existing store CLI's offline parser.

The native-linked offline regression target `test-ton-analytics-validator-adapter`
(CTest `ton-analytics-validator-adapter`) additionally exercises the shared Core
bridge mapping, runner adapter and validator renderer. Its explicitly synthetic
metadata covers ready counts, all required check subjects/observed hashes,
trusted network pins, pending reasons and adjacent election boundaries; it also
checks the production missing-raw-MC rejection path. It needs the generated TON
headers/libraries and does not open NodeDB. After syncing runner changes into the
single native build, build this target together with `ton-analytics`, then run
`ctest --test-dir BUILD/ton-analytics --output-on-failure`.

## Inputs and September selection

Supply three **existing, disjoint, canonical directories**, with no symlink
components: the primary archive root, secondary metadata directory, and facts
workdir. Use the deployment's resource/NOFILE limits appropriate to that archive.
The primary path is opened in secondary mode only; access to primary files is
read-only. All created files are in the other two directories.

Example command shape (replace every placeholder with verified inputs):

```sh
ton-analytics \
  --network mainnet --zerostate-root ROOT_HEX --zerostate-file FILE_HEX \
  --db-root /archive/db --secondary-working-dir /analytics/secondary \
  --work-dir /analytics/september-run-001 \
  --from FIRST_MC --to LAST_MC --max-anchors 4
```

`--from/--to` are inclusive. Alternatively `--anchors-file FILE` accepts strictly
increasing, unique, full MC IDs, one line `SEQNO ROOT_HEX FILE_HEX`; blank lines
and lines beginning `#` are ignored. Lists may be sparse: every selected N loads
its **own adjacent N−1**, not the previous selected list item. Non-genesis anchors
must be at least 2. Range mode selects each full ID through a separate archived
handle lookup; list mode additionally compares both hashes with the supplied ID.

Default anchor-time interval is exactly **September 2026 UTC**:
`[1788220800,1790812800)` = `[2026-09-01,2026-10-01)`. Out-of-interval MCs stop
the run. `--anchor-time-from/--anchor-time-to` explicitly override those Unix
second bounds, e.g. for boundary witnesses. This executable does not discover a
month's seqno endpoints. Supply externally selected IDs; it validates their raw
times. A delayed shard included in September may have an August transaction
time: its actual `gen_utime` is preserved, never relabelled September.

| Option | Default | Meaning |
|---|---:|---|
| `--max-anchors` | 4 | Explicit planned-run cap; maximum 100000 |
| `--max-blocks` | 256 | Per-anchor diff/tip cap; maximum 4096 |
| `--max-transactions` | 100000 | Per-anchor raw/parsed transaction cap |
| `--max-aux` | 256 | Distinct config MC reads per anchor; Supply callback reads per calculation |
| `--max-output-bytes` | 67108864 | Per-anchor NDJSON cap; no sampling/truncation |
| `--max-seconds` | 300 | Whole-process wall budget, including open/catch-up |
| `--supply` | off | Expensive exact queue-based Supply calculation |
| `--wallet-events` | off | Full bounded address event facts, not samples |
| `--nft-candidates` | off | Full bounded NFT initialization candidates |
| `--accounts-sample-limit` | 0 | Diagnostic sample, only with Accounts build option; never full baseline |

Scheduler budget is **two actor threads**, one selected anchor at a time. There
is one explicit initial catch-up; periodic catch-up is scheduled beyond the wall
budget. RocksDB/runtime support threads are library-controlled, not a claim of
exactly two OS threads. `fetch_seqno` materializes one snapshot before the runner
can check its size, so these caps do not replace deployment process memory/IO
limits. No month of cell states is retained. Supply temporarily retains at most
two full anchor views plus bounded auxiliary states inside the native calculator.

## Extraction and evidence

* **Core:** uses the corrected `verify_auxiliary_mc` and `verify_anchor` APIs.
  MC0 root/file must match the trusted network pair, the archive handle, and the
  MC state's OldMcBlocks identity. Original BoC SHA256, full block IDs, raw header,
  state update, typed state and full shard manifest checks remain explicit.
  Event processing additionally requires `continuity_status` verified. No flag
  is upgraded merely because two strings or caller booleans agree.
* **Independent event frontier:** raw predecessor full IDs of **every** included
  block must connect the previous MC's complete tip set to the current tip set,
  including unchanged tips, intermediates, split siblings and both merge parents.
  Extra/missing blocks and branches fail. This separate check does not mutate
  Core's `diff_exhaustiveness_checked=false`, assert signatures, or close a UTC day.
  Workchain births not reachable from that frontier stop rather than being guessed.
* **Flow:** calls the real `ton_analytics::flow::extract`. For each MC block it
  loads the predecessor MC config; for each shard block it loads that block's
  raw `master_ref` MC config, which may be much older than inclusion. Each full
  config-source ID is checked against the anchor's historical MC dictionary and
  independently verified. Config #8 hash, source MC/state and applied version are
  serialized per block. There is no current/post-inclusion config fallback.
  Gross fees, created, raw burned, transaction count and actual zero-sink emissions
  are emitted. V1's absent burned field stays null; emission is not delivery.
* **Validators:** `run_verified_mc` re-verifies the original MC BoC, full ID,
  post-state and trusted network pin before supplying the stage's typed anchor.
  Check codes stay in Core evidence; ready stage checks have empty failure reasons.
  Config #34 count can be ready independently of shard-range completeness.
  Frozen stake uses only the decoder's reviewed Elector code hash and its exact
  roster/sum checks. A single MC leaves historical boundary metrics pending.
  Selected-original and finished-election observations are enabled only for
  an independently checked adjacent #36 transition **and an absent matching past
  election in the prior state**, then the stage rechecks membership and totals.
  Historical election/settlement/APR/APY dependencies are not invented. The native
  renderer preserves each metric's separate value/null/status and all positions.
* **Supply (`--supply`):** invokes `calculate_global_balance_at_anchor` on N−1 and
  N. Auxiliary MCs are read by full ID from the same secondary and checked against
  anchor ancestry. Four components must sum to total. Preceding config #14 issuance
  and block count must equal the exhaustive raw flow inventory; unexpected minted
  grams, invalid components or nonzero `ΔSupply−created+burned` stop with no commit.
* **Wallets/Assets options:** parser block/transaction inventory must match raw
  Flow before extraction. Wallets resolves execution/post code with its retained
  CellDB resolver and emits **every** bounded witness/send, including pending code
  reasons. NFT candidate extraction uses its raw transaction checks. No lifetime
  baseline, reducer checkpoint, complete DAU/MAU, NFT minted or DNS sold is claimed.
  Jetton address-subset getters and DNS selection inputs are not implemented here.
* **Accounts option (optional build):** calls the actual bounded sample API with `allow_full=false`.
  Counts are explicitly diagnostic lower bounds and `network_total=null`.

Seqno-zero shard tips remain explicitly unsupported by Core's ordinary block
verifier. No fake block BoC/state-update proof is manufactured for a zerostate.

## Output, failure and resume

Successful anchor N atomically publishes:

```text
WORK/scope.txt
WORK/runner.lock
WORK/N.committed/facts.ndjson
WORK/N.committed/receipt.txt
```

The receipt stores scope digest, full MC ID, SHA256 of exact NDJSON bytes and the
first-included block coordinate inventory. Files and directories are fsynced;
renaming `N.pending` to `N.committed` is the commit point. Only a contiguous prefix
of the explicitly selected plan resumes. Same-ID completed anchors skip extraction;
changed full ID, extraction options/plan/source version, corrupt checksum, duplicate coordinates
or out-of-order completion fail. Local progress never reads the main indexer's DB.
Reuse the same workdir for retries of the same plan; use a new workdir for a new
bounded chunk. Downstream fact identities exclude run selection and do not sum
duplicates from overlapping chunks.

An extraction failure exits **1**, does not commit or advance N, and stops the
range. Independently successful Validators snapshot rows survive in
`N.failed.ndjson` with an `anchor_failure` reason when that snapshot was available.
Those rows are not a successful event batch. A wall-budget kill can leave only
uncommitted staging, retried on restart. Argument/preflight errors exit **2**.
Exit **0** means the requested extraction plan was committed locally, not that
every domain metric/day/lifetime is complete or that ClickHouse received it.

Every fact has `schema_version=1`, producer/source version, source tree SHA256,
TON checkout revision, network, zerostate root/file, full MC and predecessor IDs,
MC state hash/time, dataset, stable fact key, status and typed payload. Shard IDs
are 16-digit unsigned hex; hashes are hex; amounts and LTs are decimal strings.
Per-block source/config provenance is carried with flow. The source fingerprint
includes uncommitted runner/domain/scanner source and supplied build patches;
the TON revision is checkout HEAD, with the indexer's build patches applied.
No historical metric numbers are bundled as fixtures or asserted by this README.

## Separate store transport handoff

The current store CLI takes one **typed envelope**, not a raw runner fact. The
local, offline mapper bridges that exact contract:

```sh
python3 ton-indexer/ton-index-worker/ton-analytics/pack_spool.py \
  /analytics/september-run-001/N.committed > /analytics/envelopes.ndjson
```

It verifies the committed file checksum and emits one bounded v1 envelope per
scalar/observation. Send **each line separately** to the existing
`ton-analytics-store/cli.py ingest` through the deployment transport. It performs
no HTTP/CH operations itself and refuses pending/failed directories. Real extracted
Flow, ready Validators and zero-residual Supply become `numeric_verified` producer
facts; unsupported/missing metrics and raw address observations remain explicitly
`unresolved`, preserving their payload in provenance. No completion/publication
method is called. Large anchor evidence stays in original NDJSON with its digest;
Validators envelopes carry only the relevant metric and its complete positions.
`source_fact_sha256` hashes the canonical full fact after excluding run-selection
fields, so it is stable across overlapping plans; the receipt separately hashes
the exact original NDJSON file bytes.
Oversized store envelopes stop rather than truncate. This mapper's default input
budget is 64 MiB, output envelope budget 256000 bytes, matching the store v1 limit.

TON terminology reference consulted: `https://docs.ton.org/llms/start-here/content.md`.
Native API/verification details come from the actual checked-out module headers.
