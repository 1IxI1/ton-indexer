#include "TotalSupply.h"

#include <map>
#include <set>

#include "validator/impl/shard.hpp"
#include "crypto/block/block.h"
#include "td/utils/Timer.h"

namespace gramstat {

td::Result<schema::TotalSupply> make_total_supply(
    std::uint32_t mc_seqno, std::uint32_t gen_utime,
    const ton::validator::GlobalBalanceComponents& c) {
    for (const auto& amount : {c.total, c.accounts, c.dispatch_queue,
                              c.unprocessed_messages, c.unrecovered_validator_fees}) {
        if (amount.is_null() || !amount->is_valid() || amount->sgn() < 0 ||
            amount->to_dec_string().size() > 38) {
            return td::Status::Error("Total supply amount is not a nonnegative Decimal(38, 0)");
        }
    }
    if (td::cmp(c.total, c.accounts + c.dispatch_queue + c.unprocessed_messages + c.unrecovered_validator_fees) != 0) {
        return td::Status::Error("Total supply components do not add up to total");
    }
    // c.burned is diagnostic ValueFlow, not another deduction from this snapshot.
    return schema::TotalSupply{mc_seqno, gen_utime, c.total, c.accounts, c.dispatch_queue,
                               c.unprocessed_messages, c.unrecovered_validator_fees};
}

td::actor::Task<schema::TotalSupply> calculate_total_supply(
    schema::MasterchainBlockDataState blocks, StateLoader load_state) {
    using namespace ton::validator;
    const schema::BlockDataState* mc = nullptr;
    std::map<ton::BlockIdExt, const schema::BlockDataState*> tops;
    for (const auto& entry : blocks.shard_blocks_) {
        if (entry.block_data.is_null() || entry.block_state.is_null()) {
            co_return td::Status::Error("Total supply requires block data and state for every shard tip");
        }
        auto id = entry.block_data->block_id();
        if (id.is_masterchain()) {
            if (mc != nullptr) {
                co_return td::Status::Error("Duplicate total supply masterchain state");
            }
            mc = &entry;
        } else if (!tops.emplace(id, &entry).second) {
            co_return td::Status::Error("Duplicate total supply shard tip");
        }
    }
    if (mc == nullptr || !load_state) {
        co_return td::Status::Error("Total supply requires a masterchain state and state loader");
    }

    auto mc_state = co_await MasterchainStateQ::fetch(mc->block_data->block_id(), {}, mc->block_state);
    std::vector<GlobalBalanceShardState> shards;
    for (const auto& desc : mc_state->get_shards()) {
        auto id = desc->top_block_id();
        auto it = tops.find(id);
        if (it == tops.end()) {
            if (id.seqno() != 0) {
                co_return td::Status::Error("Total supply is missing a current shard tip");
            }
            auto state = co_await load_state(id);
            if (state.is_null() || state->get_block_id() != id) {
                co_return td::Status::Error("Total supply zerostate loader returned a different block");
            }
            shards.push_back({std::move(state), {}});
        } else {
            const auto& entry = *it->second;
            auto state = co_await ShardStateQ::fetch(id, {}, entry.block_state);
            shards.push_back({std::move(state), entry.block_data->root_cell()});
            tops.erase(it);
        }
    }
    if (!tops.empty()) {
        co_return td::Status::Error("Total supply contains a shard outside the masterchain snapshot");
    }

    auto load_aux = [load_state = std::move(load_state)](ton::BlockIdExt id)
        -> td::actor::Task<td::Ref<MasterchainState>> {
        auto state = co_await load_state(id);
        if (state.is_null() || state->get_block_id() != id || !id.is_masterchain()) {
            co_return td::Status::Error("Total supply auxiliary loader returned a different block");
        }
        td::Ref<MasterchainState> mc_state{state};
        if (mc_state.is_null()) {
            co_return td::Status::Error("Total supply auxiliary state is not a masterchain state");
        }
        co_return mc_state;
    };
    auto components = co_await calculate_global_balance_at_anchor(
        mc_state, mc->block_data->root_cell(), std::move(shards), std::move(load_aux));
    co_return make_total_supply(mc_state->get_seqno(), mc_state->get_unix_time(), components);
}

td::actor::Task<SupplyResult> calculate_incremental_supply(
    schema::MasterchainBlockDataState blocks, StateLoader load_state, SupplyCache previous) {
    using namespace ton::validator;
    td::Timer timer;
    SupplyResult result;
    std::map<ton::BlockIdExt, const schema::BlockDataState*> inputs;
    std::set<ton::BlockIdExt> tip_ids;
    const schema::BlockDataState* mc = nullptr;
    for (const auto& entry : blocks.shard_blocks_) {
        if (entry.block_data.is_null() || entry.block_state.is_null()) {
            co_return td::Status::Error("Total supply requires every shard tip's block and state");
        }
        auto id = entry.block_data->block_id();
        if (!tip_ids.insert(id).second) {
            co_return td::Status::Error("Duplicate total supply tip");
        }
        if (id.is_masterchain()) {
            if (mc) co_return td::Status::Error("Duplicate total supply masterchain state");
            mc = &entry;
        }
        inputs.emplace(id, &entry);
    }
    if (!mc || !load_state) {
        co_return td::Status::Error("Total supply requires a masterchain state and state loader");
    }
    auto mc_id = mc->block_data->block_id();
    auto mc_state = co_await MasterchainStateQ::fetch(mc_id, {}, mc->block_state);
    auto version = mc_state->get_config()->get_global_version();
    std::set<ton::BlockIdExt> expected{mc_id};
    for (const auto& desc : mc_state->get_shards()) {
        auto id = desc->top_block_id();
        expected.insert(id);
        if (!tip_ids.count(id) && id.seqno() != 0) {
            co_return td::Status::Error("Total supply is missing a current shard tip");
        }
    }
    for (const auto& id : tip_ids) {
        if (!expected.count(id)) co_return td::Status::Error("Total supply contains an unexpected shard tip " + id.to_str());
    }

    const bool consecutive = !previous.states.empty() && mc_id.seqno() == previous.mc_id.seqno() + 1;
    if (consecutive) {
        auto header = co_await block::get_block_header_info(mc->block_data->root_cell(), mc_id);
        if (header.prev.size() != 1 || header.prev.front() != previous.mc_id) {
            co_return td::Status::Error("Total supply masterchain predecessor mismatch");
        }
    }
    if (previous.states.empty()) result.stats.reset_reason = "initial";
    else if (version != previous.global_version) result.stats.reset_reason = "version";
    else if (!consecutive && mc_id != previous.mc_id) result.stats.reset_reason = "gap";
    const bool incremental = result.stats.reset_reason.empty();
    if (!incremental) previous.states.clear();

    for (const auto& entry : blocks.shard_blocks_diff_) {
        if (entry.block_data.is_null() || entry.block_state.is_null()) {
            co_return td::Status::Error("Total supply has an incomplete intermediate block");
        }
        auto id = entry.block_data->block_id();
        auto [it, inserted] = inputs.emplace(id, &entry);
        if (!inserted && it->second->block_state->get_hash() != entry.block_state->get_hash()) {
            co_return td::Status::Error("Total supply has conflicting states for one block");
        }
    }

    std::map<ton::BlockIdExt, GlobalBalanceShardState> raw;
    std::map<ton::BlockIdExt, std::vector<ton::BlockIdExt>> parents;
    std::set<ton::BlockIdExt> visited;
    std::vector<ton::BlockIdExt> pending(expected.begin(), expected.end());
    auto prepared = std::move(previous.states);
    // Discover the dependency DAG, stopping at cached tips. Never walk back
    // beyond the previous anchor. Cold initialization prepares only current tips.
    while (!pending.empty()) {
        auto id = pending.back();
        pending.pop_back();
        if (!visited.insert(id).second) continue;
        auto input = inputs.find(id);
        if (input != inputs.end() && id.seqno() != 0) {
            auto root = input->second->block_data->root_cell();
            if (root.is_null() || root->get_hash().as_bits256() != id.root_hash) {
                co_return td::Status::Error("Total supply block root hash mismatch");
            }
        }
        auto cached = prepared.find(id);
        if (cached != prepared.end()) {
            if (input != inputs.end() &&
                cached->second.state_hash != input->second->block_state->get_hash().as_bits256()) {
                co_return td::Status::Error("Total supply cached state hash mismatch");
            }
            ++result.stats.reused;
            continue;
        }
        GlobalBalanceShardState entry;
        if (input != inputs.end()) {
            if (id == mc_id) entry.state = mc_state;
            else entry.state = co_await ShardStateQ::fetch(id, {}, input->second->block_state);
            entry.block_root = input->second->block_data->root_cell();
        } else if (id.seqno() == 0) {
            entry.state = co_await load_state(id);
            if (entry.state.is_null() || entry.state->get_block_id() != id) {
                co_return td::Status::Error("Total supply zerostate loader returned a different block");
            }
        } else {
            co_return td::Status::Error("Total supply is missing intermediate block " + id.to_str());
        }
        if (incremental && id.seqno() != 0) {
            auto header = co_await block::get_block_header_info(entry.block_root, id);
            for (const auto& parent : header.prev) {
                if (parent.seqno() >= id.seqno()) {
                    co_return td::Status::Error("Total supply has a nondecreasing predecessor");
                }
                pending.push_back(parent);
            }
            parents.emplace(id, std::move(header.prev));
        }
        raw.emplace(id, std::move(entry));
    }

    // Independent shards in one dependency layer prepare in parallel. Only this
    // coroutine changes the map; detached native tasks own their input handles.
    while (!raw.empty()) {
        std::vector<ton::BlockIdExt> ids;
        std::vector<td::actor::StartedTask<PreparedGlobalBalanceState>> tasks;
        for (const auto& [id, entry] : raw) {
            std::vector<PreparedGlobalBalanceState> prev;
            bool ready = true;
            for (const auto& parent : parents[id]) {
                auto it = prepared.find(parent);
                if (it == prepared.end()) { ready = false; break; }
                prev.push_back(it->second.prepared);
            }
            if (!ready) continue;
            if (prev.empty()) ++result.stats.cold;
            else ++result.stats.with_prev;
            ids.push_back(id);
            tasks.push_back(prepare_global_balance_state(entry.state, entry.block_root, version, std::move(prev)).start());
        }
        if (ids.empty()) co_return td::Status::Error("Total supply dependency graph cannot advance");
        auto handles = co_await td::actor::all(std::move(tasks));
        for (std::size_t i = 0; i < ids.size(); ++i) {
            auto id = ids[i];
            prepared.emplace(id, PreparedSupplyState{std::move(handles[i]), raw.at(id).state->root_cell()->get_hash().as_bits256()});
            raw.erase(id);
        }
    }
    result.cache.mc_id = mc_id;
    result.cache.global_version = version;
    std::vector<PreparedGlobalBalanceState> shards;
    for (const auto& id : expected) {
        result.cache.states.emplace(id, prepared.at(id));
        if (!id.is_masterchain()) shards.push_back(prepared.at(id).prepared);
    }
    result.stats.prepare_seconds = timer.elapsed();
    td::Timer compute_timer;
    auto load_aux = [load_state = std::move(load_state)](ton::BlockIdExt id) -> td::actor::Task<td::Ref<MasterchainState>> {
        auto state = co_await load_state(id);
        if (state.is_null() || state->get_block_id() != id || !id.is_masterchain()) {
            co_return td::Status::Error("Total supply auxiliary loader returned a different block");
        }
        co_return td::Ref<MasterchainState>{state};
    };
    auto components = co_await calculate_global_balance_at_anchor(
        mc_state, mc->block_data->root_cell(), prepared.at(mc_id).prepared, std::move(shards), std::move(load_aux));
    result.snapshot = co_await make_total_supply(mc_id.seqno(), mc_state->get_unix_time(), components);
    result.stats.compute_seconds = compute_timer.elapsed();
    co_return result;
}

}  // namespace gramstat
