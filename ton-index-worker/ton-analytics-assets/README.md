# Assets diagnostic stages (STOP-gated)

The address-subset executable reads **two adjacent MC anchors** through
`DbScanner::fetch_seqno` in `dbs_secondary` mode. It emits pending JSON for 1–2
explicit wallet addresses, not a global Jetton Wallets count, CH commit, or daily
series. The separate `ton-analytics-assets-events-native` library contains an
NFT/DNS first-included-diff **candidate-only** adapter; its reducer tests are
synthetic and do not prove native linkage or first mint/sale/volume.

## Current status and permission boundary

The indexer's `external/ton` checkout is pinned to
`afe8bfbba3a9a647d455504718bebd0303dd539b` (not the old `0004f60` gitlink or
the previous prepared-reader revision). The chief's **separate** secondary
smoke on MC 89799586 succeeded with full block/state/tips and matching CH
block root/file: wall 26.27 s, CPU ~94 s, peak RSS ~2.54 GiB. It did **not**
fetch Assets account/getter evidence, establish archive completeness, or link
this target at `afe8bfb`. The startup partial metadata check is not a full
archive integrity proof.

The chief is building the unified runner in an isolated Linux build. This
directory's native targets have **not** been linked there. Chief owns the root
CMake hook, runner/`AnchorEvidence` adapter, writer and DDL. Request root
registration after `tondb-scanner` **and** `ton-analytics-core`:

```cmake
add_subdirectory(ton-analytics-core)   # unless registered already
add_subdirectory(ton-analytics-assets) # after tondb-scanner and core
```

Build both `ton-analytics-assets` and `ton-analytics-assets-events-native` in
the **same** isolated indexer/Ton `afe8bfb` CMake tree and report the link
result and exact build path. The latter needs an explicit chief-owned runner
hook; linking the runner's current standalone `NftEvents.cpp` is **not**
linking the Assets event stage. Do not duplicate sources in one target; the
chief also needs to include the new adapter/DNS source files in the runner's
source-provenance digest when wiring it. `AnchorEvidence` must be passed from
the chief's verified full-snapshot/diff path, not synthesized here.
Generated prerequisites are `external/ton/crypto/block/block-auto.{h,cpp}`
(`tlb_generate_block`), `tondb-scanner/src/tokens-tlb.{h,cpp}`
(`tlb_generate_tokens`), and build-tree
`external/ton/tdutils/td/utils/config.h`. They are absent from this unbuilt
checkout; a native syntax or link claim requires the **matching** configured
build. Do not borrow headers from the separate root `ton/` tree or start a
competing expensive Linux build.

The `TON_ASSETS_SECONDARY_SAFETY_REVIEWED` build option defaults **OFF** and
keeps the diagnostic executable from opening NodeDB. Turning it on only after
a linked `afe8bfb` build and safety review does **not** grant an Assets pilot
slot. The authorized queue is Validators → Wallets → Assets; at most one
secondary process may open the archive. Claim the slot only after Wallets
records release and the chief approves this specific command. Never open a
live archive, CH or a primary/read-only fallback just to test integration.

## Proposed bounded invocation after that separate approval

Pass every resource budget explicitly (the former 60 s CPU / 2 GiB memory
pilot is obsolete, **do not run it**):

```text
--readonly-opt-in --db-root /var/ton-work/db
--secondary-work-dir ABSOLUTE_NEW_EMPTY_PRIVATE_WORKDIR
--network mainnet --zerostate-root 64_HEX --zerostate-file 64_HEX
--from 90051907 --to 90051908 --max-wallets 1 --max-tip-roots 16
--wallet 0:64_HEX --cpu-seconds 900 --memory-mib 16384
--wall-seconds 300 --nofile-budget 1048576
```

The sample address and MC0 hashes must come from the separately reviewed
September request; the placeholders above are **not executable**. `db-root`
must be the actual primary DB path. `dbs_secondary` uses a new, separate,
canonical, empty work directory; no bind mount or host mount-table change is
needed. Do not use `dbs_readonly`, an old nonempty secondary directory, or
fallback to the live primary. Every budget flag is mandatory and bounded:
CPU 1–900 s, address space 128–16384 MiB, wall 1–300 s, NOFILE
1024–1048576. Explicit smaller diagnostic budgets are syntactically valid,
**not** defaults and inadequate for the measured cold open. RLIMITs and
wall-clock alarm are set before DB open; failure aborts. The parser checks
absolute/canonical disjoint paths and emptiness immediately before open; a
hostile concurrent rename/mount can still defeat these checks, so the pilot
requires a trusted stable filesystem. `--readonly-opt-in` means no writer,
**not** RocksDB `OpenForReadOnly`.

Only a successful, actually awaited `CatchUpMode::Force` result permits
MC0/network validation and reads; error, timeout, mismatched full IDs/roots,
missing tips, or getter uncertainty stays nonzero/pending. MC predecessor
full ID and state hash are checked for the second anchor. No consensus
signatures or externally audited getter context are supplied, so raw positive
balance is **unknown**. JSON has `writer_committed=false`,
`global_metric_complete=false`, `daily_complete=false`; no Assets rows or
publication exist. A two-MC September probe is not lifetime or day coverage.

## Offline checks (no TON/DB access)

`cmake -S ton-indexer/ton-index-worker/ton-analytics-assets -B <fresh-temp-build>`
then `cmake --build <fresh-temp-build> --target
test-ton-analytics-assets-cli test-ton-analytics-assets-facts
test-ton-analytics-assets-events` and `ctest --test-dir <fresh-temp-build>
--output-on-failure`. These targets are pure CLI/JSON/synthetic reducer tests;
they do **not** certify a native TON adapter/link, secondary catch-up, or a
NodeDB pilot.
