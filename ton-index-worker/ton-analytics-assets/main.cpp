// Separate, opt-in, bounded address-subset stage; no scheduler, CH writer or daily metric.
// STOP by default; a reviewed native link and an explicitly queued pilot are prerequisites.
#include <cstdint>
#include <string>

namespace assets_analytics {
enum class ReadStage { SecondaryCatchUp, McZeroHandle, FetchMc };

// Pure diagnostic label: the stage is where an error surfaced, not proof of
// which archive component or block caused it.
std::string read_stage_label(ReadStage stage, std::uint32_t seqno = 0) {
  switch (stage) {
    case ReadStage::SecondaryCatchUp: return "secondary_catch_up";
    case ReadStage::McZeroHandle: return "mc0_handle_lookup";
    case ReadStage::FetchMc: return "fetch_mc_seqno_" + std::to_string(seqno);
  }
  return "unknown_read_stage";
}
}  // namespace assets_analytics

// Compile the exact pure label helper without TON headers/NodeDB for offline tests.
#ifndef TON_ASSETS_STAGE_LABEL_ONLY
#include "AssetFacts.h"
#include "CliOptions.h"
#include "assets_analytics/Extractor.h"
#include "DbScanner.h"

#include "block/block-auto.h"
#include "block/block-parse.h"
#include "td/actor/coro_utils.h"
#include "common/checksum.h"
#include "td/utils/crypto.h"
#include "td/utils/logging.h"
#include "vm/cells/MerkleUpdate.h"
#include "validator/fabric.h"

#include <sys/resource.h>
#include <unistd.h>
#include <csignal>
#include <iostream>
#include <limits>
#include <map>
#include <memory>
#include <set>
#include <stdexcept>

namespace {
using namespace assets_analytics;

void demand(bool ok, const std::string& message) {
  if (!ok) throw std::runtime_error(message);
}

// The original BoC bytes, not the repr hash or BlockData::file_hash metadata.
td::Bits256 verify_block(const schema::BlockDataState& entry, const ton::BlockIdExt& id) {
  demand(static_cast<bool>(entry.handle) && entry.handle->id() == id && entry.block_data.not_null() &&
         entry.block_data->block_id() == id && entry.block_state.not_null(), "missing/mismatched block/state full ID");
  auto boc = entry.block_data->data();
  demand(!boc.empty() && td::sha256_bits256(boc.as_slice()) == id.file_hash, "block BoC file hash mismatch");
  auto raw = entry.block_data->root_cell();
  demand(raw.not_null() && raw->get_hash().as_bits256() == id.root_hash, "block root hash mismatch");
  block::gen::Block::Record b;
  demand(tlb::unpack_cell(raw, b) && vm::MerkleUpdate::validate(b.state_update).is_ok(),
         "invalid block/state Merkle update");
  td::Bits256 old_hash, new_hash;
  auto update = vm::load_cell_slice(b.state_update);
  demand(update.fetch_ulong(8) == 4 && update.fetch_bits_to(old_hash.bits(), 256) &&
         update.fetch_bits_to(new_hash.bits(), 256) &&
         new_hash == entry.block_state->get_hash().as_bits256(), "post-state hash mismatch");
  block::gen::ShardStateUnsplit::Record state;
  demand(tlb::unpack_cell(entry.block_state, state) &&
         block::ShardId(state.shard_id) == block::ShardId(id), "shard identity mismatch");
  return old_hash;
}

bool match_hex(const std::string& provided, const std::string& from_source) {
  if (provided.size() != from_source.size()) return false;
  for (size_t i = 0; i < provided.size(); ++i) {
    auto c = provided[i];
    if (c >= 'A' && c <= 'F') c = static_cast<char>(c - 'A' + 'a');
    if (c != from_source[i]) return false;
  }
  return true;
}

struct Snapshot {
  Anchor anchor;
  td::Bits256 old_hash;
  std::vector<Observation> observations;
};

// DbScanner::request_catch_up takes its promise BEFORE the mode, so the
// standard promise-last actor ask helper cannot call it directly.
class RequireSecondaryCatchUp final : public td::actor::Actor {
 public:
  explicit RequireSecondaryCatchUp(td::actor::ActorId<DbScanner> scanner) : scanner_(scanner) {}
  void check(td::Promise<td::Unit> promise) {
    td::actor::send_closure(scanner_, &DbScanner::request_catch_up, std::move(promise),
                            ton::validator::CatchUpMode::Force);
  }
 private:
  td::actor::ActorId<DbScanner> scanner_;
};

Snapshot materialize(const schema::MasterchainBlockDataState& data, const CliOptions& o, uint32_t n) {
  demand(!data.shard_blocks_.empty() && data.shard_blocks_.size() <= o.max_tip_roots + 1,
         "missing or over-limit MC/tip roots");
  const auto& mc = data.shard_blocks_.front();
  demand(static_cast<bool>(mc.handle), "missing MC handle");
  const auto id = mc.handle->id();
  demand(id.is_masterchain() && id.id.seqno == n, "unexpected MC block ID");
  auto old_hash = verify_block(mc, id);
  block::gen::Block::Record mc_block;
  demand(tlb::unpack_cell(mc.block_data->root_cell(), mc_block) &&
         mc_block.global_id == (o.network == "mainnet" ? -239 : -3),
         "MC raw block global_id/network mismatch");
  block::gen::ShardStateUnsplit::Record mc_state;
  block::gen::McStateExtra::Record extra;
  block::ShardConfig shards;
  demand(tlb::unpack_cell(mc.block_state, mc_state) && mc_state.custom.not_null() &&
         tlb::unpack_cell(mc_state.custom->prefetch_ref(), extra) && shards.unpack(extra.shard_hashes),
         "cannot decode MC shard configuration");

  Anchor anchor;
  anchor.network = o.network;
  anchor.zerostate = o.zerostate_root;
  anchor.gen_utime = mc_state.gen_utime;
  anchor.mc = {id, mc.block_state->get_hash().as_bits256(), mc.block_state, true};
  // Independently enumerate the canonical MC ShardHashes dictionary, not merely
  // the scanner's supplied tips (which may silently omit a seqno-zero tip).
  std::map<ton::BlockIdExt, const schema::BlockDataState*> loaded;
  for (size_t i = 1; i < data.shard_blocks_.size(); ++i) {
    const auto& tip = data.shard_blocks_[i];
    demand(static_cast<bool>(tip.handle) && !tip.handle->id().is_masterchain() &&
           loaded.emplace(tip.handle->id(), &tip).second, "duplicate/invalid shard tip");
  }
  auto expected = shards.get_shard_hash_ids_ext(true);
  demand(!expected.empty() && expected.size() == loaded.size() && expected.size() <= o.max_tip_roots,
         "incomplete or over-limit shard tip manifest");
  for (const auto& tip_id : expected) {
    demand(tip_id.id.seqno > 0 && loaded.count(tip_id) == 1, "missing/genesis shard tip");
    auto* tip = loaded.at(tip_id);
    verify_block(*tip, tip_id);
    anchor.shard_tips.push_back({tip_id, tip->block_state->get_hash().as_bits256(), tip->block_state, true});
  }
  anchor.caller_attests_complete_tip_manifest = true;  // equality with MC ShardHashes checked above
  auto config = block::ConfigInfo::extract_config(mc.block_state, id,
                       block::ConfigInfo::needCapabilities | block::ConfigInfo::needLibraries);
  demand(config.is_ok(), "cannot extract historical config from MC state root");
  anchor.config = std::shared_ptr<block::ConfigInfo>(config.move_as_ok());
  anchor.caller_attests_config_from_this_mc_root = true;  // extracted above from this exact root
  // No GetterContextAudit is supplied: zero-LT/seed and missing prev-blocks
  // are unaudited. Getter results, including a positive raw balance, stay unknown.
  std::vector<block::StdAddress> addresses;
  for (const auto& wallet : o.wallets) {
    td::Bits256 hash;
    auto text = wallet.substr(wallet.find(':') + 1);
    // BitArray::from_hex returns the number of parsed bits (or -1), not td::Status.
    demand(hash.from_hex(td::Slice(text)) == 256, "bad wallet hash");
    addresses.emplace_back(wallet[0] == '-' ? -1 : 0, hash);
  }
  Budget budget{o.max_wallets, o.max_tip_roots, 1u << 20};
  auto facts = observe_wallets(anchor, addresses, budget);
  demand(facts.is_ok() && facts.ok().size() == addresses.size(), "address extraction incomplete");
  return {std::move(anchor), old_hash, facts.move_as_ok()};
}

td::actor::Task<td::Unit> run(td::actor::ActorId<DbScanner> scanner,
                              td::actor::ActorId<RequireSecondaryCatchUp> gate, CliOptions o,
                              std::shared_ptr<int> exit_code) {
  // Fail on secondary initial/explicit catch-up error, never fall back to a
  // primary or RocksDB OpenForReadOnly against a live primary.
  auto caught_up = co_await td::actor::ask(gate, &RequireSecondaryCatchUp::check).wrap();
  if (caught_up.is_error())
    co_return caught_up.move_as_error_prefix(read_stage_label(ReadStage::SecondaryCatchUp) + ": ");
  // Bind the user-provided network identity to the archived MC zerostate ID,
  // not merely a caller-supplied label. An absent MC0 handle fails closed.
  auto genesis = co_await td::actor::ask(scanner, &DbScanner::get_mc_block_handle, 0).wrap();
  if (genesis.is_error())
    co_return genesis.move_as_error_prefix(read_stage_label(ReadStage::McZeroHandle) + ": ");
  auto zero = genesis.move_as_ok();
  if (!zero || !zero->id().is_masterchain() || zero->id().id.seqno != 0 ||
      !match_hex(o.zerostate_root, zero->id().root_hash.to_hex()) ||
      !match_hex(o.zerostate_file, zero->id().file_hash.to_hex()))
    co_return td::Status::Error("archived MC zerostate does not match explicit network root/file identity");
  td::Bits256 previous_state;
  ton::BlockIdExt previous_id;
  std::vector<std::string> rows;
  for (auto n : {o.from, o.to}) {
    auto fetched = co_await td::actor::ask(scanner, &DbScanner::fetch_seqno, n).wrap();
    if (fetched.is_error())
      co_return fetched.move_as_error_prefix(read_stage_label(ReadStage::FetchMc, n) + ": ");
    try {
      auto current = materialize(fetched.move_as_ok(), o, n);
      if (n == o.to) {
        demand(current.old_hash == previous_state, "MC predecessor state root mismatch");
        demand(current.anchor.mc.block_id.id.seqno == previous_id.id.seqno + 1,
               "MC predecessor seqno mismatch");
        auto typed_r = ton::validator::create_shard_state(current.anchor.mc.block_id,
                                                          current.anchor.mc.root);
        demand(typed_r.is_ok(), "cannot read MC predecessor from typed post-state");
        td::Ref<ton::validator::MasterchainState> typed{typed_r.move_as_ok()};
        ton::BlockIdExt ancestor;
        demand(typed.not_null() && typed->get_block_id() == current.anchor.mc.block_id &&
               typed->get_old_mc_block_id(previous_id.id.seqno, ancestor) && ancestor == previous_id,
               "MC predecessor full ID mismatch");
      }
      previous_state = current.anchor.mc.state_root_hash;
      previous_id = current.anchor.mc.block_id;
      BatchMeta meta{o.network, o.zerostate_root, "assets-address-subset-v1",
                     current.anchor.mc.block_id.to_str(), current.anchor.mc.state_root_hash.to_hex(),
                     current.anchor.gen_utime};
      meta.zerostate_file_hash = o.zerostate_file;
      // JSON is diagnostic and pending; no CH commit, no global count, no external audit.
      rows.push_back(render_batch_json(meta, current.observations));
      *exit_code = 1;
    } catch (const vm::VmError& e) {
      co_return e.as_status("assets: ");
    } catch (const std::exception& e) {
      co_return td::Status::Error(std::string(e.what()));
    }
  }
  for (const auto& row : rows) std::cout << row << '\n';
  co_return td::Unit();
}

void limit_process(const CliOptions& opts) {
  const uint64_t requested_bytes = static_cast<uint64_t>(opts.memory_mib) * 1024 * 1024;
  demand(requested_bytes <= std::numeric_limits<rlim_t>::max() &&
         opts.cpu_seconds <= std::numeric_limits<rlim_t>::max() &&
         opts.nofile_budget <= std::numeric_limits<rlim_t>::max(), "resource budget does not fit rlim_t");
  rlimit memory{static_cast<rlim_t>(requested_bytes), static_cast<rlim_t>(requested_bytes)};
  rlimit cpu{static_cast<rlim_t>(opts.cpu_seconds), static_cast<rlim_t>(opts.cpu_seconds)};
  rlimit nofile{static_cast<rlim_t>(opts.nofile_budget), static_cast<rlim_t>(opts.nofile_budget)};
  demand(setrlimit(RLIMIT_NOFILE, &nofile) == 0, "cannot enforce NOFILE budget");
  demand(setrlimit(RLIMIT_AS, &memory) == 0, "cannot enforce memory budget");
  demand(setrlimit(RLIMIT_CPU, &cpu) == 0, "cannot enforce CPU budget");
  alarm(opts.wall_seconds); // wall-clock hard-stop, including stalled I/O; no timed-out result can be published
}
}  // namespace

int main(int argc, char** argv) {
  CliOptions opts;
  try {
    opts = parse_cli(std::vector<std::string>(argv + 1, argv + argc));
#if !defined(TON_ASSETS_SECONDARY_SAFETY_REVIEWED) || TON_ASSETS_SECONDARY_SAFETY_REVIEWED != 1
    throw std::runtime_error("STOP: secondary TON integration safety review/build not approved");
#endif
    limit_process(opts);
    revalidate_paths(opts);
  } catch (const std::exception& e) {
    std::cerr << "ton-analytics-assets: " << e.what() << '\n';
    return 2; // never open NodeDB on option, gate, or resource-limit failure
  }
  SET_VERBOSITY_LEVEL(verbosity_WARNING);
  td::actor::Scheduler scheduler({2});
  td::actor::ActorOwn<DbScanner> scanner;
  td::actor::ActorOwn<RequireSecondaryCatchUp> gate;
  auto code = std::make_shared<int>(1); // pending by default
  auto watcher = td::create_shared_destructor([] { td::actor::SchedulerContext::get().stop(); });
  scheduler.run_in_context([&, watcher = std::move(watcher)]() mutable {
    // One explicit checked catch-up, no periodic catch-up racing the two reads
     // during the explicit bounded wall-clock limit.
    scanner = td::actor::create_actor<DbScanner>("secondary-assets", opts.db_root.string(), dbs_secondary,
                                                 opts.secondary_work_dir.string(), 3600.0f, false);
    gate = td::actor::create_actor<RequireSecondaryCatchUp>("assets-secondary-catchup", scanner.get());
    auto done = td::PromiseCreator::lambda([watcher = std::move(watcher), code](td::Result<td::Unit> result) {
      if (result.is_error()) {
        std::cout << "{\"dataset\":\"assets\",\"status\":\"pending\",\"writer_committed\":false,"
                     "\"global_metric_complete\":false,\"reason\":\"secondary source or validation failed\"}\n";
        std::cerr << "assets stage pending: " << result.move_as_error().to_string() << '\n';
        *code = 1;
      }
    });
    td::connect(std::move(done), run(scanner.get(), gate.get(), opts, code).start());
  });
  scheduler.run();
  return *code;
}
#endif  // TON_ASSETS_STAGE_LABEL_ONLY
