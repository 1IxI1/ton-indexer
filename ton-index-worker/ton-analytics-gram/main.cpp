// Bounded audit with a secondary DB; never write the primary or use OpenForReadOnly on a live DB.
#include "DbScanner.h"
#include "record.h"
#include "crypto/block/block-auto.h"
#include "crypto/block/block.h"
#include "crypto/block/block-parse.h"
#include "crypto/block/mc-config.h"
#include "crypto/vm/cells/MerkleUpdate.h"
#include "td/actor/coro_utils.h"
#include "td/utils/logging.h"
#include "validator/fabric.h"
#include "validator/global-balance-calculator.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <limits>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace {
using namespace ton;
using namespace ton::validator;

void require(bool ok, const std::string& error) {
  if (!ok) throw std::runtime_error(error);
}

template <class T>
T required(td::Result<T> result, const std::string& what) {
  if (result.is_error()) throw std::runtime_error(what + ": " + result.move_as_error().to_string());
  return result.move_as_ok();
}

struct Options {
  std::string db_root;
  std::string secondary_working_dir;
  std::string network;
  uint32_t from = 0, to = 0;
};

uint32_t seqno(const std::string& value) {
  require(!value.empty() && value.find_first_not_of("0123456789") == std::string::npos,
          "seqno must be an unsigned decimal integer");
  auto number = std::stoull(value);
  require(number <= std::numeric_limits<uint32_t>::max(), "seqno out of range");
  return static_cast<uint32_t>(number);
}

Options parse_options(int argc, char** argv) {
  Options opts;
  bool from = false, to = false;
  for (int i = 1; i < argc; i += 2) {
    require(i + 1 < argc, "each option requires a value");
    std::string key = argv[i], value = argv[i + 1];
    if (key == "--db-root" && opts.db_root.empty()) opts.db_root = value;
    else if (key == "--secondary-working-dir" && opts.secondary_working_dir.empty()) opts.secondary_working_dir = value;
    else if (key == "--network" && opts.network.empty()) opts.network = value;
    else if (key == "--from" && !from) { opts.from = seqno(value); from = true; }
    else if (key == "--to" && !to) { opts.to = seqno(value); to = true; }
    else throw std::runtime_error("unknown/duplicate option: " + key);
  }
  require(from && to && opts.from > 0 && opts.to > opts.from &&
              static_cast<uint64_t>(opts.to) - opts.from < 10,
          "require 2..10 consecutive non-genesis MC anchors: --from N --to M");
  require(opts.network == "mainnet" || opts.network == "testnet", "require --network mainnet|testnet");
  require(!opts.db_root.empty() && !opts.secondary_working_dir.empty(),
          "require --db-root and --secondary-working-dir (separate existing directories)");
  auto [primary, secondary] = gram::validate_secondary_paths(opts.db_root, opts.secondary_working_dir);
  opts.db_root = primary.string();
  opts.secondary_working_dir = secondary.string();
  return opts;
}

std::string id_json(const BlockIdExt& id) {
  return "{\"workchain\":" + std::to_string(id.id.workchain) +
         ",\"shard\":" + gram::json_string(gram::shard_hex(id.id.shard)) +
         ",\"seqno\":" + std::to_string(id.id.seqno) +
         ",\"root_hash\":" + gram::json_string(gram::lowercase_hex(id.root_hash.to_hex())) +
         ",\"file_hash\":" + gram::json_string(gram::lowercase_hex(id.file_hash.to_hex())) + "}";
}

struct Snapshot {
  BlockIdExt id;
  int32_t global_id;
  std::vector<BlockIdExt> raw_mc_predecessors;
  bool raw_after_split;
  td::Bits256 previous_state_hash;
  td::Ref<MasterchainState> state;
  td::Ref<vm::Cell> state_root;
  GlobalBalanceComponents money;
  std::vector<BlockIdExt> tips;
  std::vector<std::string> tip_state_hashes;
  size_t included_count = 0;
  td::RefInt256 included_created = td::zero_refint();
};

struct Validated {
  td::Ref<ShardState> state;
  td::Ref<vm::Cell> block_root;
  td::Bits256 previous_state_hash;
};

Validated validate_entry(const schema::BlockDataState& entry, const BlockIdExt& expected) {
  require(entry.handle != nullptr && entry.handle->id() == expected, "block handle full ID mismatch: " + expected.to_str());
  require(entry.block_data.not_null() && entry.block_data->block_id() == expected,
          "block data full ID mismatch: " + expected.to_str());
  require(entry.block_state.not_null(), "missing state root: " + expected.to_str());
  // TON hashes the original serialized block BoC, not a re-serialized root.
  // BlockData::file_hash() just returns its stored ID; it does not prove bytes.
  const auto boc = entry.block_data->data();
  require(gram::block_file_hash_matches(boc.as_slice(), expected.file_hash),
          "raw block BoC file_hash mismatch or bytes unavailable: " + expected.to_str());
  auto block_root = entry.block_data->root_cell();
  require(block_root.not_null() && block_root->get_hash().as_bits256() == expected.root_hash,
          "block root hash mismatch: " + expected.to_str());
  block::gen::Block::Record block;
  require(tlb::unpack_cell(block_root, block), "invalid raw block: " + expected.to_str());
  // MerkleUpdate contains the hash of the post-state, not the block root hash.
  require(vm::MerkleUpdate::validate(block.state_update).is_ok(), "invalid state update: " + expected.to_str());
  auto update = vm::load_cell_slice(block.state_update);
  td::Bits256 old_hash, new_hash;
  require(update.fetch_ulong(8) == 4 && update.fetch_bits_to(old_hash.bits(), 256) &&
              update.fetch_bits_to(new_hash.bits(), 256) &&
              new_hash == entry.block_state->get_hash().as_bits256(),
          "post-state hash differs from block state_update: " + expected.to_str());
  auto state = required(create_shard_state(expected, entry.block_state), "create typed state " + expected.to_str());
  require(state.not_null() && state->get_block_id() == expected &&
              state->root_cell().not_null() && state->root_cell()->get_hash() == entry.block_state->get_hash() &&
              state->get_global_id() == block.global_id,
          "typed state identity/root mismatch: " + expected.to_str());
  return {std::move(state), std::move(block_root), old_hash};
}

// Same config-14 transition algorithm as TON global-balance-calculator.cpp::compare_global_balance.
// Count ALL newly included shard blocks (including intermediate blocks), not just changed tips
// or shard_blocks_diff_. That vector is a useful independent coverage diagnostic, but can
// contain multiple blocks of one shard and is not the multiplier after a split/merge.
std::pair<td::RefInt256, uint64_t> created(const Snapshot& prev, const Snapshot& next) {
  auto config = required(block::ConfigInfo::extract_config(prev.state_root, prev.id,
                                                              block::ConfigInfo::needCapabilities),
                         "read preceding MC configuration");
  auto param = config->get_config_param(14);
  require(param.not_null(), "missing preceding MC config #14");
  block::gen::BlockCreateFees::Record fees;
  td::RefInt256 mc = td::zero_refint(), base = td::zero_refint();
  require(tlb::unpack_cell(param, fees) &&
              block::tlb::t_Grams.as_integer_to(fees.masterchain_block_fee, mc) &&
              block::tlb::t_Grams.as_integer_to(fees.basechain_block_fee, base), "invalid config #14");
  auto sum = mc;
  uint64_t included = 1;  // The successor MC block itself.
  for (const auto& desc : next.state->get_shards()) {
    const auto left = prev.state->get_shard_from_config(desc->shard() - 1, false);
    const auto right = prev.state->get_shard_from_config(desc->shard() + 1, false);
    require(left.is_null() == right.is_null(), "inconsistent predecessor shard configuration");
    int64_t prior = 0;
    if (left.is_null()) {
      // Workchain first appears: every block up to this tip is new.
    } else if (left->shard() == desc->shard()) {
      prior = left->top_block_id().seqno();
    } else if (left->shard() == right->shard()) {
      require(desc->shard().pfx_len() > 0 && left->shard() == shard_parent(desc->shard()),
              "invalid shard split");
      prior = left->top_block_id().seqno();
    } else {
      require(left->shard() == shard_child(desc->shard(), true) &&
                  right->shard() == shard_child(desc->shard(), false), "invalid shard merge");
      prior = std::max(left->top_block_id().seqno(), right->top_block_id().seqno());
    }
    int64_t n = static_cast<int64_t>(desc->top_block_id().seqno()) - prior;
    require(n >= 0, "shard seqno regressed");
    sum += (base >> shard_prefix_length(desc->shard())) * n;
    included += static_cast<uint64_t>(n);
  }
  require(sum->is_valid(), "created amount overflow");
  return {sum, included};
}

std::string components_json(const Snapshot& s) {
  const auto& c = s.money;
  return "{\"accounts\":" + gram::amount(c.accounts) +
         ",\"dispatch_queue\":" + gram::amount(c.dispatch_queue) +
         ",\"unprocessed_messages\":" + gram::amount(c.unprocessed_messages) +
         ",\"unrecovered_validator_fees\":" + gram::amount(c.unrecovered_validator_fees) +
         ",\"total\":" + gram::amount(c.total) +
         ",\"burned\":" + gram::amount(c.burned) + "}";
}

std::string tips_json(const Snapshot& s) {
  std::string result = "[";
  for (size_t i = 0; i < s.tips.size(); ++i) {
    if (i) result += ',';
    result += "{\"id\":" + id_json(s.tips[i]) +
              ",\"state_hash\":" + gram::json_string(s.tip_state_hashes[i]) + "}";
  }
  return result + ']';
}

td::actor::Task<Snapshot> fetch_snapshot(td::actor::ActorId<DbScanner> scanner, uint32_t seqno,
                                          const std::string& network) {
  auto fetched = co_await td::actor::ask(scanner, &DbScanner::fetch_seqno, seqno).wrap();
  if (fetched.is_error()) co_return fetched.move_as_error();
  auto data = fetched.move_as_ok();
  try {
    require(!data.shard_blocks_.empty(), "missing masterchain snapshot");
    const auto& mc_entry = data.shard_blocks_.front();
    require(mc_entry.handle != nullptr, "missing MC handle");
    const auto mc_id = mc_entry.handle->id();
    require(mc_id.is_masterchain() && mc_id.id.seqno == seqno, "wrong masterchain anchor");
    auto mc_valid = validate_entry(mc_entry, mc_id);
    auto raw_header = required(block::get_block_header_info(mc_valid.block_root, mc_id),
                               "decode raw MC block predecessor " + mc_id.to_str());
    require(raw_header.prev.size() == 1 && !raw_header.after_split && raw_header.mc_blkid == raw_header.prev.front(),
            "raw MC header lacks exactly one valid predecessor");
    td::Ref<MasterchainState> mc{mc_valid.state};
    require(mc.not_null() && mc->get_block_id() == mc_id, "typed MC state ID mismatch");
    require(mc->get_global_id() == (network == "mainnet" ? -239 : -3), "network/global_id mismatch");

    std::map<BlockIdExt, schema::BlockDataState> loaded;
    for (size_t i = 1; i < data.shard_blocks_.size(); ++i) {
      const auto& tip = data.shard_blocks_[i];
      require(tip.handle != nullptr, "null shard tip handle");
      require(loaded.emplace(tip.handle->id(), tip).second, "duplicate shard tip");
    }
    const auto expected = mc->get_shards();
    require(loaded.size() <= expected.size(), "extra shard tips in scanner result");
    std::vector<GlobalBalanceShardState> shards;
    std::vector<BlockIdExt> ids;
    std::vector<std::string> hashes;
    for (const auto& desc : expected) {
      auto id = desc->top_block_id();
      require(!id.is_masterchain(), "MC ID in shard tips");
      auto it = loaded.find(id);
      if (it == loaded.end()) {
        // DbScanner::IndexQuery omits seqno-zero tips. Fetch them by *full* ID;
        // an unavailable genesis block/state is a hard error, never a zero balance.
        require(id.id.seqno == 0, "missing non-genesis top shard tip: " + id.to_str());
        auto one = co_await td::actor::ask(scanner, &DbScanner::fetch_block_by_id, id).wrap();
        if (one.is_error()) co_return td::Status::Error(id.to_str() + ": " + one.move_as_error().to_string());
        it = loaded.emplace(id, one.move_as_ok()).first;
      }
      auto validated = validate_entry(it->second, id);
      require(validated.state->get_global_id() == mc->get_global_id(), "shard tip network/global_id mismatch");
      hashes.push_back(gram::lowercase_hex(it->second.block_state->get_hash().to_hex()));
      shards.push_back({std::move(validated.state), std::move(validated.block_root)});
      ids.push_back(id);
    }
    require(loaded.size() == expected.size(), "unexpected shard tip / incomplete MC configuration");
    // Independent evidence for the issuance comparison: use ALL first-included
    // blocks, not only changed tips. This also catches missing intermediate
    // blocks, while the snapshot calculator still receives tips only.
    std::set<BlockIdExt> included_ids;
    td::RefInt256 included_created = td::zero_refint();
    for (const auto& entry : data.shard_blocks_diff_) {
      require(entry.handle != nullptr, "missing included block handle");
      auto id = entry.handle->id();
      require(included_ids.insert(id).second, "duplicate included block full ID");
      // Validate each intermediate state update as well as MC/current tips.
      auto validated = validate_entry(entry, id);
      require(validated.state->get_global_id() == mc->get_global_id(), "included block network/global_id mismatch");
      block::gen::Block::Record raw;
      block::ValueFlow flow;
      require(tlb::unpack_cell(validated.block_root, raw) && flow.unpack(vm::load_cell_slice_ref(raw.value_flow)),
              "invalid included block/value flow: " + id.to_str());
      require(flow.created.grams.not_null() && flow.minted.grams.not_null() &&
                  flow.minted.grams == td::zero_refint(), "unexpected minted grams in included block");
      included_created += flow.created.grams;
    }
    require(included_ids.count(mc_id) == 1 && included_created->is_valid(),
            "missing included MC block or created amount overflow");
    // No manager actor or fallback network read: every processed_upto dependency
    // must resolve through the same read-only archive, by full BlockIdExt.
    auto aux = [scanner, global_id = mc->get_global_id()](BlockIdExt id) -> td::actor::Task<td::Ref<MasterchainState>> {
      if (!id.is_masterchain()) co_return td::Status::Error("aux ID is not masterchain");
      auto r = co_await td::actor::ask(scanner, &DbScanner::fetch_block_by_id, id).wrap();
      if (r.is_error()) co_return r.move_as_error();
      auto entry = r.move_as_ok();
      try {
        auto validated = validate_entry(entry, id);
        td::Ref<MasterchainState> state{validated.state};
        require(state.not_null() && state->get_block_id() == id && state->get_global_id() == global_id,
                "aux MC typed ID/global_id mismatch");
        co_return state;
      } catch (const vm::VmError& e) {
        co_return e.as_status("aux " + id.to_str() + ": ");
      } catch (const std::exception& e) {
        co_return td::Status::Error("aux " + id.to_str() + ": " + e.what());
      }
    };
    auto result = co_await calculate_global_balance_at_anchor(mc, mc_valid.block_root, std::move(shards), aux).wrap();
    if (result.is_error()) co_return result.move_as_error();
    auto money = result.move_as_ok();
    require(money.accounts.not_null() && money.dispatch_queue.not_null() &&
                money.unprocessed_messages.not_null() && money.unrecovered_validator_fees.not_null() &&
                money.total.not_null() && money.burned.not_null() && money.burned->is_valid(),
            "calculator returned missing/invalid component");
    require(money.total == money.accounts + money.dispatch_queue + money.unprocessed_messages +
                               money.unrecovered_validator_fees, "components do not add to total");
    co_return Snapshot{mc_id, mc->get_global_id(), std::move(raw_header.prev), raw_header.after_split,
                       mc_valid.previous_state_hash, std::move(mc), mc_entry.block_state,
                       std::move(money), std::move(ids), std::move(hashes), included_ids.size(), included_created};
  } catch (const vm::VmError& e) {
    co_return e.as_status("snapshot: ");
  } catch (const std::exception& e) {
    co_return td::Status::Error(std::string(e.what()));
  }
}

td::actor::Task<td::Unit> audit(td::actor::ActorId<DbScanner> scanner, Options opts,
                                std::shared_ptr<int> exit_code) {
  auto start = std::chrono::steady_clock::now();
  auto elapsed = [&] {
    return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count();
  };
  std::string prefix = "{\"network\":" + gram::json_string(opts.network) +
                       ",\"calc_version\":\"ton-global-balance-0004f60d\""
                       ",\"source\":\"node_db_secondary\",\"mc_signatures_checked\":false";
  auto previous = co_await fetch_snapshot(scanner, opts.from, opts.network).wrap();
  if (previous.is_error()) {
    std::cout << prefix << ",\"mc_seqno\":" << opts.from << ",\"status\":\"error\",\"error\":"
              << gram::json_string(previous.move_as_error().to_string()) << ",\"duration_ms\":" << elapsed() << "}\n";
    *exit_code = 1;
    co_return td::Unit();
  }
  auto prev = previous.move_as_ok();
  for (uint64_t n = static_cast<uint64_t>(opts.from) + 1; n <= opts.to; ++n) {
    if (n > static_cast<uint64_t>(opts.from) + 1) start = std::chrono::steady_clock::now();
    auto current = co_await fetch_snapshot(scanner, static_cast<uint32_t>(n), opts.network).wrap();
    if (current.is_error()) {
      std::cout << prefix << ",\"previous_mc\":" << id_json(prev.id) << ",\"mc_seqno\":" << n
                << ",\"status\":\"error\",\"error\":"
                << gram::json_string(current.move_as_error().to_string()) << ",\"duration_ms\":" << elapsed() << "}\n";
      *exit_code = 1;
      break;
    }
    auto next = current.move_as_ok();
    std::string row = prefix + ",\"previous_mc\":" + id_json(prev.id) +
                      ",\"mc\":" + id_json(next.id) +
                      ",\"raw_mc_predecessor\":" + id_json(next.raw_mc_predecessors.front()) +
                      ",\"previous_state_hash\":" +
                      gram::json_string(gram::lowercase_hex(prev.state_root->get_hash().to_hex())) +
                      ",\"state_hash\":" +
                      gram::json_string(gram::lowercase_hex(next.state_root->get_hash().to_hex())) +
                      ",\"global_id\":" + std::to_string(next.global_id) +
                      ",\"previous_components_nanoton\":" + components_json(prev) +
                      ",\"components_nanoton\":" + components_json(next) +
                      ",\"previous_tip_count\":" + std::to_string(prev.tips.size()) +
                      ",\"tip_count\":" + std::to_string(next.tips.size()) +
                      ",\"included_block_count\":" + std::to_string(next.included_count) +
                      ",\"included_created_nanoton\":" + gram::amount(next.included_created) +
                      ",\"previous_tips\":" + tips_json(prev) + ",\"tips\":" + tips_json(next);
    try {
      BlockIdExt ancestor;
      require(next.id.id.seqno == prev.id.id.seqno + 1 &&
                  gram::single_predecessor_matches(next.raw_mc_predecessors, prev.id, next.raw_after_split) &&
                  next.state->get_old_mc_block_id(prev.id.id.seqno, ancestor) && ancestor == prev.id &&
                  next.previous_state_hash == prev.state_root->get_hash().as_bits256(),
              "nonconsecutive MC predecessor (raw full ID, state dict ID or state-update old hash mismatch)");
      auto [minted, expected_count] = created(prev, next);
      require(next.included_count == expected_count && next.included_created == minted,
              "first-included block coverage or raw ValueFlow.created differs from config #14");
      auto diff = gram::residual(prev.money.total, next.money.total, minted, next.money.burned);
      require(diff->is_valid(), "invariant arithmetic overflow");
      const bool ok = diff == td::zero_refint();
      std::cout << row << ",\"created_nanoton\":" << gram::amount(minted)
                << ",\"burned_nanoton\":" << gram::amount(next.money.burned)
                << ",\"delta_nanoton\":" << gram::amount(next.money.total - prev.money.total)
                << ",\"residual_nanoton\":" << gram::amount(diff)
                << ",\"status\":\"" << (ok ? "verified" : "invariant_mismatch") << "\""
                << ",\"duration_ms\":" << elapsed() << "}\n";
      if (!ok) { *exit_code = 1; break; }
    } catch (const vm::VmError& e) {
      std::cout << row << ",\"status\":\"error\",\"error\":" << gram::json_string(e.get_msg())
                << ",\"duration_ms\":" << elapsed() << "}\n";
      *exit_code = 1;
      break;
    } catch (const std::exception& e) {
      std::cout << row << ",\"status\":\"error\",\"error\":" << gram::json_string(e.what())
                << ",\"duration_ms\":" << elapsed() << "}\n";
      *exit_code = 1;
      break;
    }
    prev = std::move(next);
  }
  co_return td::Unit();
}
}  // namespace

int main(int argc, char** argv) {
  Options opts;
  try {
    opts = parse_options(argc, argv);
  } catch (const std::exception& e) {
    std::cerr << "usage: ton-analytics-gram --network mainnet|testnet --db-root DIR "
                 "--secondary-working-dir SEPARATE_DIR --from N --to M\n"
              << e.what() << '\n';
    return 2;
  }
  SET_VERBOSITY_LEVEL(verbosity_WARNING);
  td::actor::Scheduler scheduler({2});
  td::actor::ActorOwn<DbScanner> scanner;
  auto code = std::make_shared<int>(0);
  auto watcher = td::create_shared_destructor([] { td::actor::SchedulerContext::get().stop(); });
  scheduler.run_in_context([&, watcher = std::move(watcher)]() mutable {
    scanner = td::actor::create_actor<DbScanner>("secondary-supply", opts.db_root, dbs_secondary,
                                                  std::make_optional(opts.secondary_working_dir));
    auto done = td::PromiseCreator::lambda([watcher = std::move(watcher), code](td::Result<td::Unit> result) {
      if (result.is_error()) {
        std::cout << "{\"status\":\"error\",\"error\":"
                  << gram::json_string(result.move_as_error().to_string()) << "}\n";
        *code = 1;
      }
    });
    td::connect(std::move(done), audit(scanner.get(), opts, code).start());
  });
  scheduler.run();
  return *code;
}
