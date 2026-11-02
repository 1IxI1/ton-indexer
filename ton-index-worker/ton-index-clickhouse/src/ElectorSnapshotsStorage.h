#pragma once
#include "InsertManagerBase.h"
#include "clickhouse/client.h"
namespace staking_history::clickhouse_storage {
inline constexpr const char* SCHEMA_SQL = R"SQL(
CREATE TABLE IF NOT EXISTS elector_stake_states (
    mc_seqno UInt32, gen_utime DateTime('UTC'), elector_address String,
    code_hash String, data_hash String, previous_data_hash String,
    complete Bool, penalty_activity Bool, error String,
    applications_complete Bool, applications_error String,
    elections Array(Tuple(
        election_id UInt32, vset_hash String, unfreeze_at UInt32, stake_held UInt32,
        total_stake Decimal(38,0),
        positions Array(Tuple(pubkey String, holder String, weight UInt64,
                              stake Decimal(38,0), banned Bool, adnl Nullable(String))))),
    applications Array(Tuple(
        election_id UInt32, elect_close UInt32, min_stake Decimal(38,0),
        total_stake Decimal(38,0), finished Bool, failed Bool,
        participants Array(Tuple(pubkey String, holder String, adnl String,
                                 stake Decimal(38,0), max_factor UInt32)))),
    CONSTRAINT one_application_set CHECK length(applications) <= 1
) ENGINE=ReplacingMergeTree PARTITION BY toYYYYMM(gen_utime) ORDER BY mc_seqno
)SQL";
inline constexpr const char* SET_SCHEMA_SQL = R"SQL(
CREATE TABLE IF NOT EXISTS validator_set_states (
    mc_seqno UInt32, gen_utime DateTime('UTC'), config_hash String, config_boc String
) ENGINE=ReplacingMergeTree PARTITION BY toYYYYMM(gen_utime) ORDER BY mc_seqno
)SQL";
inline constexpr const char* VIEW_SQL = R"SQL(
CREATE VIEW IF NOT EXISTS elector_frozen_positions AS
SELECT mc_seqno, gen_utime, e.election_id AS election_id, e.vset_hash AS vset_hash,
       e.unfreeze_at AS unfreeze_at, e.stake_held AS stake_held,
       p.pubkey AS pubkey, p.holder AS holder, p.weight AS weight,
       p.stake AS stake, p.banned AS banned
FROM (
  SELECT mc_seqno, gen_utime, arrayJoin(elections) AS e
  FROM elector_stake_states FINAL WHERE complete
) ARRAY JOIN e.positions AS p
)SQL";
inline constexpr const char* HOLDER_SCHEMA_SQL = R"SQL(
CREATE TABLE IF NOT EXISTS stake_holder_states (
    account String, mc_seqno UInt32, gen_utime DateTime('UTC'),
    code_hash String, data_hash String, kind String, pool Nullable(String), error String
) ENGINE=ReplacingMergeTree PARTITION BY toYYYYMM(gen_utime) ORDER BY (account,mc_seqno)
)SQL";
void insert_states(clickhouse::Client& client, const std::vector<InsertTaskStruct>& tasks);
clickhouse::Block states_block(const std::vector<schema::ElectorSnapshot>& states);
clickhouse::Block holders_block(const std::vector<schema::StakeHolder>& states);
}
