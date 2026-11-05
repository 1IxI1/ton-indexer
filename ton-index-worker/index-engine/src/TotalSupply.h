#pragma once

#include <map>
#include "IndexData.h"
#include "validator/global-balance-calculator.hpp"

namespace gramstat {

using StateLoader = std::function<td::actor::Task<td::Ref<ton::validator::ShardState>>(ton::BlockIdExt)>;

// Uses the current MC and all its top shard states from the existing pipeline.
// The loader is only for auxiliary MC states and seqno-zero shard tips omitted
// by DbScanner::fetch_seqno. Errors propagate; no partial snapshot is returned.
td::actor::Task<schema::TotalSupply> calculate_total_supply(
    schema::MasterchainBlockDataState blocks, StateLoader load_state);

struct PreparedSupplyState {
    ton::validator::PreparedGlobalBalanceState prepared;
    td::Bits256 state_hash;
};

// Only the last successful MC and its current shard tips. No history chain.
struct SupplyCache {
    ton::BlockIdExt mc_id;
    int global_version = -1;
    std::map<ton::BlockIdExt, PreparedSupplyState> states;
};

struct SupplyStats {
    std::size_t reused = 0;
    std::size_t cold = 0;
    std::size_t with_prev = 0;
    double prepare_seconds = 0;
    double compute_seconds = 0;
    std::string reset_reason;
};

struct SupplyResult {
    schema::TotalSupply snapshot;
    SupplyCache cache;
    SupplyStats stats;
};

// Value-in/value-out: a failure never advances or mutates the caller's cache.
// The pipeline already supplies intermediate blocks in shard_blocks_diff_.
// Only zerostates and auxiliary MC states need the loader. Missing intermediate
// blocks on a consecutive step are errors, not an implicit expensive rescan.
td::actor::Task<SupplyResult> calculate_incremental_supply(
    schema::MasterchainBlockDataState blocks, StateLoader load_state, SupplyCache previous = {});

td::Result<schema::TotalSupply> make_total_supply(
    std::uint32_t mc_seqno, std::uint32_t gen_utime,
    const ton::validator::GlobalBalanceComponents& components);

}  // namespace gramstat
