# Staked Gram

`gramstat-aggregate --handlers staking` calculates daily staking amounts, breaks
them down by staking contract type, and reports stake associated with Telegram
network infrastructure.

The calculations use two sources:

* **Indexer PostgreSQL database:** historical states of the Elector, the system
  contract that accepts validator applications and holds their locked stake.
* **Session Stats:** timestamped observations of validator network addresses and
  their network operators, used for Telegram attribution.

## Stake amounts

An **election** selects validators for a validation round. An elected validator's
**position** is the stake recorded for its public key in that election. The
**stake holder** is the account recorded by the Elector for that position; it can
be a wallet, a nominator pool or a liquid-staking controller.

The daily calculation includes every election whose locked stakes are still
recorded in the Elector at the reference block for that day.

| Field | Meaning |
| --- | --- |
| `submitted_nanogram` | Final total of applications accepted for those elections, including applications from candidates who were not selected |
| `selected_nanogram` | Principal initially locked for the selected validators in those elections |
| `remaining_nanogram` | Principal that remains locked, after reductions |
| `frozen_principal_reduction_nanogram` | `selected_nanogram - remaining_nanogram` for the positions still recorded in the Elector |

These fields describe successive stages of the same funds and should not be
added together. A holder participating in two elections has two separate
positions. Rewards, withdrawable Elector credits and funds held in pool accounts
are outside the remaining-principal amount.

An election leaves the calculation when a successfully read Elector state no
longer contains it. Its scheduled release time, `unfreeze_at`, does not establish
that release has occurred.

The principal-reduction field covers positions that remain locked. It is not a
daily or all-time sum of fines. Position records also include the Elector's
`banned` flag, which must be considered when analysing confiscation on release.
Releasing a position does not by itself count as a fine.

### Verifying the initial amounts

The aggregator accepts an election's first recorded stake as its initial
selected amount when:

1. The preceding successfully read state contains no such election.
2. The Elector's data hashes link the two records: `previous_data_hash` in the
   new record equals `data_hash` in the preceding record. The Elector address
   and code hash also match.
3. The first record includes the matching completed, successful applications.
4. There was no complaint or complaint-vote activity in that masterchain block.
5. The currently recorded validator-public-key/holder pairs match the initial
   positions, and their principal has not increased.

If indexing starts after selection or the required records are missing,
submitted, selected and principal reduction are `NULL`. The remaining amount
can still be calculated from a successfully read Elector state.

### Units and precision

All amounts use integer nanoGRAM: `1 GRAM = 1,000,000,000 nanoGRAM`. Database
columns use PostgreSQL `numeric(38,0)` or ClickHouse `Decimal(38,0)`, and the Go
calculations use `big.Int`.

## Data collection

The indexer compares the Elector's stored data before and after its transactions.
When the data changes, it calls `past_elections` once using the final state of
the masterchain block. It also reads the state at key blocks—masterchain blocks
that record configuration updates—and at the explicit starting block of an
indexing range.

`past_elections` supplies the elections and their locked positions.
`participant_list_extended` supplies the accepted applications and is called
at most once during processing of a masterchain block. Both get-methods execute with the
configuration and timestamp of the corresponding masterchain block.

Each **state record** contains the complete returned list of elections and
positions. The parser checks the entries and verifies that position amounts
sum to the election total. Changes to rewards can produce another record with
unchanged principal amounts.

A failed get-method or malformed result produces an incomplete record. Failure
to load the source state causes the indexer to retry the block. A successfully
read empty list means no locked positions remain. An incomplete record means
the amount is unknown; the aggregator does not substitute an earlier amount.

For example:

| Masterchain block | Recorded locked principal |
| --- | --- |
| 100 | Holder A: 100 GRAM; holder B: 200 GRAM |
| 200, after a fine | Holder A: 95 GRAM; holder B: 200 GRAM |
| 300, after release | Successfully read empty list |

The records preserve the change from 300 to 295 GRAM and the later release.

## Source tables

| Object | Contents |
| --- | --- |
| `elector_stake_states` | One complete or incomplete state record per masterchain block number (`mc_seqno`), with elections, positions, applications and Elector hashes |
| `elector_frozen_positions` | View exposing positions from complete records as rows keyed by `(mc_seqno, election_id, pubkey)` |
| `elector_frozen_elections` (PostgreSQL) | Indexed election records used to locate the first recorded state of an election |
| `elector_stake_positions` (PostgreSQL) | Position records belonging to an election and masterchain block, including holder, weight, amount, `banned` and ADNL |
| `elector_applications` (PostgreSQL) | Accepted-application totals and completion status for each recorded Elector state |
| `elector_application_participants` (PostgreSQL) | Individual applications belonging to each application record |
| `stake_holder_states` | Account classification by `(account, mc_seqno)`, including code/data hashes, parent pool and any classification error |
| `validator_set_states` | Blockchain configuration parameter 34, which contains the current validator set, recorded at key blocks and indexing-range boundaries |

These tables are populated during ordinary indexing, independently of
`--gramstat`.

**PostgreSQL:** migration 1.3.2 creates the objects in `public`. They remain in
PostgreSQL when Kvrocks is used for current account states. Records are committed
in the same transaction as their blocks. Reindexing a masterchain block replaces
its state record and the associated election rows.

**ClickHouse:** the indexer creates the source tables at startup and writes state
records before their blocks. Each Elector state is one `ReplacingMergeTree` row
containing typed `Array(Tuple(...))` columns for elections, positions and
applications. `applications_complete` indicates whether the read succeeded.
On success, an empty applications array means no active election applications;
otherwise it contains one entry. Holder classifications use individual columns, with a nullable
pool address. Queries must use `FINAL` before expanding arrays;
`elector_frozen_positions` already does this. Replacing a record also removes
positions no longer present in its list.

## Staking contract classification

The indexer classifies the final states of changed masterchain accounts,
including contract upgrades and account removal. When collecting an Elector
state, it reuses those results and reads other holders from the loaded blockchain
state. Each holder is examined at most once per masterchain block.

| Contract type | Identification |
| --- | --- |
| Standard nominator pool | Contract code hash recognised by `NominatorPoolContract` |
| Single nominator v1.0/v1.1 | [Published Orbs code hashes](https://github.com/orbs-network/single-nominator#official-code-hash) |
| Standard liquid-staking controller | Parent pool returned at zero-based index 12 by `get_validator_controller_data` |
| Hipo controller | Treasury returned at zero-based index 1 by `get_loan_state` |
| wsTON proxy | Address registry in [`calculate.go`](../ton-index-go/internal/gramstat/handlers/staking/calculate.go), applicable from 2026-10-17 11:20 UTC |

Daily calculations use each holder's latest classification at or before the
reference block. Unsupported code, missing records and failed get-methods are
classified as `unknown`. The wsTON rule applies only to its listed proxy
addresses within the registry's applicable period.

The `breakdown` field partitions remaining principal into `liquid_staking`,
`nominator_pool`, `single_nominator` and `unknown`. Liquid-staking amounts include
any validator self-stake held through those contracts; they measure elected
stake rather than total pool assets or customer deposits. See
[TON Docs: liquid staking](https://docs.ton.org/nodes/staking/liquid-staking).

## Daily calculation and Telegram attribution

For a completed UTC day, the reference block is the last indexed masterchain
block strictly before the next day. For an unfinished day, it is limited by the
requested calculation time and available indexed blocks. Days without Elector
changes use the latest preceding state record.

The Telegram calculation matches each position's ADNL identifier—the validator's
network address identifier—to Session Stats observations. It selects the latest
record in the 24 hours ending at the reference block's timestamp, ordered by
`(created_timestamp, record_id)`.

A record with `geoip_isp = 'Telegram Messenger'` assigns the position to Telegram
infrastructure. Missing operator information or conflicting records leave the
position's operator unknown. This classification describes network infrastructure,
not ownership of the stake.

| Field | Meaning |
| --- | --- |
| `telegram_observed_nanogram` | Principal assigned to Telegram by the available observations |
| `telegram_unknown_nanogram` | Principal without an unambiguous network-operator observation |
| `telegram_nanogram` | Exact Telegram-attributed amount, populated when `telegram_unknown_nanogram` is zero |

All three fields are `NULL` when the Elector principal itself is unknown.
Telegram attribution is independent of contract type: a Telegram position can
also use a single-nominator contract. Do not add it to the contract-type breakdown.

## Output and operation

Results are stored in `gramstat.staking_daily`, a
`ReplacingMergeTree(calculated_at)` table keyed by UTC day. The handler processes
requested dates in batches of at most seven days. By default it refreshes the
recent window configured by `--lookback-days`, including the current day.
`is_partial` identifies an unfinished day, and `status` reports missing data or
incomplete classification. If a source query fails, the handler returns an error
and preserves previously published rows for the affected batch.

```sql
SELECT day, remaining_nanogram, submitted_nanogram, selected_nanogram,
       frozen_principal_reduction_nanogram, breakdown,
       telegram_nanogram, telegram_unknown_nanogram, status
FROM gramstat.staking_daily FINAL ORDER BY day;
```

To configure the calculation:

1. Apply PostgreSQL migration 1.3.2 and run the indexer. Use
   `--rerun-last-migration` when updating an already-applied version 1.3.2.
2. Apply the output-table SQL printed by `gramstat-aggregate --print-schema`.
3. Configure `GRAMSTAT_PG_DSN`, the output ClickHouse connection through
   `GRAMSTAT_CH_*`, and read-only Session Stats access through `GRAMSTAT_SS_*`.
4. Run `gramstat-aggregate --handlers staking`. Supply `--from YYYY-MM-DD
   --to YYYY-MM-DD` to select a historical period; `--to` is exclusive.

Historical calculations require the Elector and holder records for the requested
period. Populate them by reindexing the relevant blocks with `--from N --to M
--force`. Start before validator selection to establish initial submitted and
selected amounts. Starting during a validation round can establish its remaining
principal while leaving initial amounts unknown.
