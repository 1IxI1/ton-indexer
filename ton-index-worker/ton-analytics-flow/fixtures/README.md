# Native-probe regression coordinates (not raw BoC fixtures)

The following expected fields were independently observed with the read-only
`scripts/tonstat_native_probe.cpp` on archived blocks (see
`docs/TONSTAT_GRAM_AND_TON_TECHNICAL.md`, "Node-DB read-only pilot"). They are
**not** executable raw-block fixtures: the local checkout contains no archive
BoCs or matching build-generated headers. `test.cpp` now constructs a small
native InMsg leaf with nonzero pre-v12 IHR and checks the versioned augmentation,
plus synthetic transaction/message counters; neither validates a complete raw
block. Once historical BoCs and full IDs are available, add offline decode
tests matching these rows and tests with multiple out-messages with identical
hashes and index-distinct identities.

| source | block gen_utime | MC inclusion | gross nanoTON | created nanoTON | burned v2 nanoTON |
| --- | ---: | ---: | ---: | ---: | ---: |
| MC 98654748 | 1791849599 | 98654748 | 0 | 1700000000 | 153800 |
| shard 103223420 | 1791849599 | 98654748 | 307601 | 1000000000 | absent (v1) |
| MC 98654749 | 1791849600 | 98654749 | 0 | 1700000000 | 4808492 |
| shard 103223421 | 1791849599 | 98654749 | 9616984 | 1000000000 | absent (v1) |
| MC 98654750 | 1791849600 | 98654750 | 0 | 1700000000 | 681789 |
| shard 103223422 | 1791849600 | 98654750 | 1363579 | 1000000000 | absent (v1) |

In particular `shard 103223421` is dated *before* its MC inclusion day.
