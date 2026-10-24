// Two-MC diagnostic producer only. No ClickHouse, scheduler, lifetime baseline,
// event checkpoint, publication claim, or readonly/primary NodeDB fallback.
#include "WalletPilot.h"

#include <iostream>
#include <vector>

#if defined(TON_WALLETS_TON_ADAPTER_AVAILABLE) && TON_WALLETS_TON_ADAPTER_AVAILABLE == 1
#include "WalletEventExtractor.h"
#include "WalletRawInventory.h"
#include "WalletStage.h"
#include "WalletMetrics.h"
#include "DbScanner.h"
#include "td/actor/coro_utils.h"
#include "common/checksum.h"
#include "common/errorcode.h"
#include "td/utils/crypto.h"
#include "td/utils/logging.h"
#include "block/block-auto.h"
#include "block/block-parse.h"
#include "vm/cells/MerkleUpdate.h"
#include "validator/fabric.h"

#include <sys/resource.h>
#include <unistd.h>
#include <algorithm>
#include <map>
#include <memory>
#include <set>
#include <sstream>
#include <stdexcept>

namespace {
using ton_analytics::wallets::cli::WalletCliOptions;
namespace events = ton_analytics::wallets::events;
namespace pilot = ton_analytics::wallets::pilot;
namespace raw = ton_analytics::wallets::raw_inventory;
namespace stage = ton_analytics::wallets::stage;
namespace wallets = ton_analytics::wallets;

void require(bool ok, const char* why) {
  if (!ok) throw std::runtime_error(why);
}

void limit_process() {
  rlimit memory{static_cast<rlim_t>(pilot::kAddressSpaceLimitBytes),
                static_cast<rlim_t>(pilot::kAddressSpaceLimitBytes)};
  rlimit cpu{static_cast<rlim_t>(pilot::kCpuLimitSeconds),
             static_cast<rlim_t>(pilot::kCpuLimitSeconds)};
  require(setrlimit(RLIMIT_AS, &memory) == 0 && setrlimit(RLIMIT_CPU, &cpu) == 0,
          "could not enforce address-space/CPU limits");
  ::alarm(pilot::kWallLimitSeconds); // includes stalled I/O; never emit a partial batch
}

bool hex_equal(const std::string& want, const std::string& actual) {
  if (want.size() != actual.size()) return false;
  for (size_t i = 0; i < want.size(); ++i) {
    char c = want[i];
    if (c >= 'A' && c <= 'F') c = static_cast<char>(c - 'A' + 'a');
    if (c != actual[i]) return false;
  }
  return true;
}

static_assert(ton::ErrorCode::notready == 651, "MC0 fallback must match the native TON notready code");

// Check the original BoC bytes, representation root, state-update post hash,
// and the shard identity before handing any cell to ParseQuery.
td::Bits256 verify(const schema::BlockDataState& item, const ton::BlockIdExt& id,
                   int32_t global_id) {
  require(item.handle && item.handle->id() == id && item.block_data.not_null() &&
          item.block_state.not_null() && item.block_data->block_id() == id,
          "block/state/handle full IDs missing or mismatched");
  auto raw = item.block_data->root_cell();
  require(raw.not_null() && raw->get_hash().as_bits256() == id.root_hash &&
          !item.block_data->data().empty() &&
          td::sha256_bits256(item.block_data->data().as_slice()) == id.file_hash,
          "block root or file hash mismatch");
  block::gen::Block::Record b;
  require(tlb::unpack_cell(raw, b) && b.global_id == global_id &&
          vm::MerkleUpdate::validate(b.state_update).is_ok(), "block global_id/update invalid");
  td::Bits256 old_hash, new_hash;
  auto update = vm::load_cell_slice(b.state_update);
  require(update.fetch_ulong(8) == 4 && update.fetch_bits_to(old_hash.bits(), 256) &&
          update.fetch_bits_to(new_hash.bits(), 256) &&
          new_hash == item.block_state->get_hash().as_bits256(), "block post-state hash mismatch");
  block::gen::ShardStateUnsplit::Record state;
  require(tlb::unpack_cell(item.block_state, state) &&
          block::ShardId(state.shard_id) == block::ShardId(id), "block state shard identity mismatch");
  return old_hash;
}

int64_t block_time(const schema::BlockDataState& item) {
  block::gen::Block::Record block;
  block::gen::BlockInfo::Record info;
  block::gen::ShardStateUnsplit::Record state;
  require(tlb::unpack_cell(item.block_data->root_cell(), block) && block.info.not_null() &&
          tlb::unpack_cell(block.info, info) && tlb::unpack_cell(item.block_state, state) &&
          info.gen_utime == state.gen_utime, "raw BlockInfo/state time disagrees");
  return info.gen_utime;
}

std::vector<ton::BlockIdExt> raw_predecessors(const schema::BlockDataState& item, uint32_t mc_seqno,
                                               ton::BlockIdExt& referenced_mc) {
  std::vector<ton::BlockIdExt> previous;
  bool after_split = false;
  const auto id = item.handle->id();
  require(block::unpack_block_prev_blk_ext(item.block_data->root_cell(), id, previous,
                                           referenced_mc, after_split).is_ok(),
          "cannot decode full predecessor IDs from raw block header");
  const auto& metadata = item.handle->prev();
  require(previous.size() <= 2 && pilot::same_unique_full_ids(previous, metadata),
          "raw header predecessor root/file IDs disagree with handle metadata");
  if (previous.size() == 2) {
    require(previous[0].id != previous[1].id, "ambiguous raw predecessor coordinates");
  }
  for (const auto& predecessor : previous) {
    require(predecessor.id.seqno < id.id.seqno &&
            predecessor.root_hash != ton::RootHash::zero() &&
            predecessor.file_hash != ton::FileHash::zero(),
            "raw predecessor is absent, ambiguous or has missing full hashes");
  }
  if (id.is_masterchain()) {
    require(previous.size() == 1 && !after_split && referenced_mc == previous.front(),
            "masterchain raw predecessor is not unique");
  } else {
    require(referenced_mc.is_masterchain() && referenced_mc.id.seqno < mc_seqno &&
            referenced_mc.root_hash != ton::RootHash::zero() &&
            referenced_mc.file_hash != ton::FileHash::zero(),
            "raw shard header lacks a complete MC reference");
  }
  return previous;
}

std::set<ton::BlockIdExt> tips(const schema::BlockDataState& mc) {
  block::gen::ShardStateUnsplit::Record state;
  block::gen::McStateExtra::Record extra;
  block::ShardConfig config;
  require(tlb::unpack_cell(mc.block_state, state) && state.custom.not_null() &&
          tlb::unpack_cell(state.custom->prefetch_ref(), extra) &&
          config.unpack(extra.shard_hashes), "MC shard-tip manifest missing");
  auto ids = config.get_shard_hash_ids_ext(true);
  return {ids.begin(), ids.end()};
}

struct Anchor {
  ton::BlockIdExt mc;
  td::Bits256 post_state;
  td::Bits256 pre_state;
  std::set<ton::BlockIdExt> tip_ids;
  std::map<ton::BlockIdExt, int64_t> tip_times;
  std::map<ton::BlockIdExt, int64_t> header_times;
  std::map<ton::BlockIdExt, std::vector<ton::BlockIdExt>> header_predecessors;
  schema::MasterchainBlockDataState data; // owns cells through parsing/extraction
};

Anchor inspect(schema::MasterchainBlockDataState data, const WalletCliOptions& opts, uint32_t n) {
  require(!data.shard_blocks_.empty() && data.shard_blocks_.size() <= opts.max_tip_roots + 1,
          "missing/over-limit MC or shard-tip manifest");
  require(!data.shard_blocks_diff_.empty() && data.shard_blocks_diff_.size() <= opts.max_blocks,
          "missing/over-limit included block list");
  const auto& mc = data.shard_blocks_.front();
  require(mc.handle && mc.handle->id().is_masterchain() && mc.handle->id().id.seqno == n,
          "wrong MC full identity");
  require(data.shard_blocks_diff_.front().handle &&
          data.shard_blocks_diff_.front().handle->id() == mc.handle->id(),
          "ParseQuery requires the MC block first in the included diff");
  const int32_t global_id = opts.network == "mainnet" ? -239 : -3;
  auto old = verify(mc, mc.handle->id(), global_id);
  auto typed_result = ton::validator::create_shard_state(mc.handle->id(), mc.block_state);
  require(typed_result.is_ok(), "cannot verify shard MC references from typed state");
  td::Ref<ton::validator::MasterchainState> typed{typed_result.move_as_ok()};
  require(typed.not_null() && typed->get_block_id() == mc.handle->id(),
          "typed MC post-state full ID differs from block handle");
  auto expected = tips(mc);
  require(!expected.empty() && expected.size() <= opts.max_tip_roots &&
          expected.size() + 1 == data.shard_blocks_.size(), "incomplete MC shard-tip manifest");
  std::set<ton::BlockIdExt> loaded;
  std::map<ton::BlockIdExt, int64_t> tip_times;
  for (size_t i = 1; i < data.shard_blocks_.size(); ++i) {
    const auto& tip = data.shard_blocks_[i];
    require(tip.handle && !tip.handle->id().is_masterchain() && tip.handle->id().id.seqno > 0 &&
            expected.count(tip.handle->id()) == 1 && loaded.insert(tip.handle->id()).second,
            "missing, duplicate or genesis shard tip");
    verify(tip, tip.handle->id(), global_id);
    require(tip_times.emplace(tip.handle->id(), block_time(tip)).second,
            "duplicate verified tip time");
  }
  std::set<ton::BlockIdExt> diff;
  std::map<ton::BlockIdExt, int64_t> header_times;
  std::map<ton::BlockIdExt, std::vector<ton::BlockIdExt>> header_predecessors;
  for (const auto& item : data.shard_blocks_diff_) {
    require(item.handle && diff.insert(item.handle->id()).second,
            "missing or duplicate first-included block handle");
    verify(item, item.handle->id(), global_id);
    require(header_times.emplace(item.handle->id(), block_time(item)).second,
            "duplicate verified included-block time");
    ton::BlockIdExt referenced_mc;
    require(header_predecessors.emplace(item.handle->id(), raw_predecessors(item, n, referenced_mc)).second,
            "duplicate raw predecessor record");
    if (!item.handle->id().is_masterchain()) {
      ton::BlockIdExt canonical_ref;
      require(typed->get_old_mc_block_id(referenced_mc.id.seqno, canonical_ref) &&
              canonical_ref == referenced_mc,
              "raw shard MC reference differs from canonical typed MC ancestry");
      require(item.handle->inited_masterchain_ref_block() && item.handle->masterchain_ref_block() == n,
              "diff block not first-included by this MC");
    }
  }
  require(diff.count(mc.handle->id()) == 1, "MC block absent from first-included diff");
  const auto mc_time = header_times.at(mc.handle->id());
  for (const auto& [id, time] : tip_times) {
    auto found = header_times.find(id);
    require(time <= mc_time && (found == header_times.end() || found->second == time),
            "shard tip has future or conflicting raw header time");
  }
  for (const auto& [id, time] : header_times) {
    require(id.is_masterchain() || time <= mc_time,
            "included shard block time exceeds MC block time");
  }
  return {mc.handle->id(), mc.block_state->get_hash().as_bits256(), old,
          std::move(expected), std::move(tip_times), std::move(header_times),
          std::move(header_predecessors), std::move(data)};
}

// Walk raw header FULL-ID predecessors (independently checked against handle
// metadata above) from canonical tips to prior tips. Reject extra/missing
// blocks; this is not a lifetime/day coverage or publication attestation.
void verify_pair(const Anchor& before, const Anchor& after) {
  require(after.mc.id.seqno == before.mc.id.seqno + 1 && after.pre_state == before.post_state,
          "MC state predecessor mismatch");
  require(after.header_times.at(after.mc) >= before.header_times.at(before.mc),
          "MC time regressed across adjacent anchors");
  auto state = ton::validator::create_shard_state(after.mc,
                    after.data.shard_blocks_.front().block_state);
  require(state.is_ok(), "could not inspect typed MC state");
  td::Ref<ton::validator::MasterchainState> typed{state.move_as_ok()};
  ton::BlockIdExt ancestor;
  require(typed.not_null() && typed->get_block_id() == after.mc &&
          typed->get_old_mc_block_id(before.mc.id.seqno, ancestor) && ancestor == before.mc &&
          after.header_predecessors.at(after.mc).size() == 1 &&
          after.header_predecessors.at(after.mc).front() == before.mc,
          "MC full-ID predecessor mismatch");

  std::set<ton::BlockIdExt> new_blocks;
  for (const auto& [id, previous] : after.header_predecessors) {
    if (!id.is_masterchain()) new_blocks.insert(id);
  }
  std::set<ton::BlockIdExt> reached, visited;
  std::vector<ton::BlockIdExt> queue(after.tip_ids.begin(), after.tip_ids.end());
  while (!queue.empty()) {
    auto id = queue.back();
    queue.pop_back();
    if (before.tip_ids.count(id)) {
      require(after.tip_times.count(id) == 0 ||
              after.tip_times.at(id) == before.tip_times.at(id),
              "unchanged tip time disagrees with previous anchor");
      reached.insert(id);
      continue;
    }
    if (!visited.insert(id).second) continue;
    require(new_blocks.count(id) == 1, "tip ancestry lacks first-included block");
    const auto time = after.header_times.at(id);
    require(time <= after.header_times.at(after.mc), "shard block time exceeds including MC time");
    for (const auto& predecessor : after.header_predecessors.at(id)) {
      require(predecessor.id.seqno > 0, "uncertified shard genesis boundary");
      const auto old_time = before.tip_times.find(predecessor);
      const auto newer_time = after.header_times.find(predecessor);
      require(old_time != before.tip_times.end() || newer_time != after.header_times.end(),
              "missing raw predecessor time");
      require(time >= (old_time != before.tip_times.end() ? old_time->second : newer_time->second),
              "shard descendant time regressed");
      queue.push_back(predecessor);
    }
  }
  require(reached == before.tip_ids && visited.size() == new_blocks.size(),
          "independent tip graph does not equal scanner diff");
}

// Built from native TL-B, never from events::Batch or ParseQuery. The first
// anchor has individually verified block IDs/MC ref tags, but not a complete
// predecessor frontier; only anchor two can assert a complete graph diff.
struct SourceInventory {
  std::vector<raw::Result> blocks;
  size_t transactions = 0;
  size_t accounts = 0;
  size_t out_messages = 0;
  size_t cell_references = 0;
};

SourceInventory read_source(const Anchor& anchor, const WalletCliOptions& opts,
                            size_t& run_transactions, size_t& run_accounts,
                            size_t& run_out_messages, size_t& run_cell_references) {
  constexpr size_t kMaxCellsAcrossRun = 2'000'000;
  const size_t max_out_messages = 5 * opts.max_transactions; // conservative abort, not truncation
  SourceInventory out;
  out.blocks.reserve(anchor.data.shard_blocks_diff_.size());
  for (const auto& item : anchor.data.shard_blocks_diff_) {
    const auto& id = item.handle->id();
    // inspect() already checked original BoC file SHA256, root, state update,
    // raw full predecessor IDs vs handle metadata, and shard MC reference.
    // The MC's typed full predecessor is checked before this call.
    raw::CallerProof proof{id, true, true,
        "wallets:file-root-state+header-handle+mc-ref:" + id.root_hash.to_hex()};
    raw::Limits limits{opts.max_transactions - run_accounts,
                       opts.max_transactions - run_transactions,
                       max_out_messages - run_out_messages,
                       kMaxCellsAcrossRun - run_cell_references};
    auto result = raw::build(item, proof, limits);
    require(result.inventory.gen_utime == anchor.header_times.at(id),
            "raw inventory BlockInfo time differs from independently decoded header/state");
    out.transactions += result.inventory.transactions.size();
    out.accounts += result.account_count;
    out.out_messages += result.out_message_count;
    out.cell_references += result.reachable_cell_references;
    run_transactions += result.inventory.transactions.size();
    run_accounts += result.account_count;
    run_out_messages += result.out_message_count;
    run_cell_references += result.reachable_cell_references;
    out.blocks.push_back(std::move(result));
  }
  require(run_transactions <= opts.max_transactions && run_accounts <= opts.max_transactions &&
          run_out_messages <= max_out_messages && run_cell_references <= kMaxCellsAcrossRun,
          "run-wide raw inventory cap exceeded");
  return out;
}

wallets::AccountStatus parsed_status(schema::AccountStatus status) {
  switch (status) {
    case schema::nonexist: return wallets::AccountStatus::nonexist;
    case schema::uninit: return wallets::AccountStatus::uninit;
    case schema::active: return wallets::AccountStatus::active;
    case schema::frozen: return wallets::AccountStatus::frozen;
  }
  throw std::runtime_error("unknown parsed transaction account status");
}

struct ParsedCounts {
  size_t transactions = 0;
  size_t post_accounts = 0;
  size_t out_messages = 0;
};

ParsedCounts compare_parsed(const ParsedBlock& parsed, const Anchor& anchor,
                            const SourceInventory& source) {
  require(parsed.blocks_.size() == source.blocks.size(), "parsed block inventory incomplete");
  size_t raw_accounts = 0;
  ParsedCounts counts;
  for (size_t i = 0; i < parsed.blocks_.size(); ++i) {
    const auto& b = parsed.blocks_[i];
    const auto& native = anchor.data.shard_blocks_diff_[i].handle->id();
    const auto& independent = source.blocks[i];
    require(b.workchain == native.id.workchain &&
            static_cast<uint64_t>(b.shard) == native.id.shard && b.seqno == native.id.seqno &&
            b.root_hash == td::base64_encode(native.root_hash.as_slice()) &&
            b.file_hash == td::base64_encode(native.file_hash.as_slice()) &&
            b.gen_utime == independent.inventory.gen_utime &&
            b.transactions.size() == independent.inventory.transactions.size(),
            "parsed block ID/time/transaction count differs from raw block");
    std::map<std::pair<std::string, uint64_t>, const stage::RawTransaction*> raw_txs;
    for (const auto& tx : independent.inventory.transactions) {
      require(raw_txs.emplace(std::make_pair(tx.account, tx.lt), &tx).second,
              "duplicate independently decoded raw transaction");
    }
    for (const auto& tx : b.transactions) {
      const auto account = std::to_string(tx.account.workchain) + ":" + tx.account.addr.to_hex();
      auto found = raw_txs.find({account, tx.lt});
      require(found != raw_txs.end(), "parsed transaction missing from raw inventory");
      const auto& raw_tx = *found->second;
      require(tx.hash.to_hex() == raw_tx.hash_hex && tx.now == raw_tx.now &&
              tx.account_state_hash_before.to_hex() == raw_tx.pre_state_hash_hex &&
              tx.account_state_hash_after.to_hex() == raw_tx.post_state_hash_hex &&
              parsed_status(tx.orig_status) == raw_tx.orig &&
              parsed_status(tx.end_status) == raw_tx.end,
              "parsed transaction identity/HASH_UPDATE/status differs from raw TL-B");
      counts.out_messages += tx.out_msgs.size();
      raw_txs.erase(found);
    }
    require(raw_txs.empty(), "parsed transaction list truncated");
    raw_accounts += independent.account_count;
    counts.transactions += b.transactions.size();
  }
  counts.post_accounts = parsed.account_states_.size();
  require(counts.transactions == source.transactions && raw_accounts == source.accounts &&
          counts.out_messages == source.out_messages && counts.post_accounts == source.accounts,
          "raw vs parsed account/transaction/out-message inventory incomplete");
  return counts;
}

std::string json_string(const std::string& s) {
  std::string out = "\"";
  for (unsigned char c : s) {
    if (c == '"' || c == '\\') { out.push_back('\\'); out.push_back(c); }
    else if (c < 0x20 || c > 0x7e) out.push_back('?');
    else out.push_back(c);
  }
  out.push_back('"');
  return out;
}

std::string id_json(const ton::BlockIdExt& id) {
  std::ostringstream s;
  s << "{\"workchain\":" << id.id.workchain << ",\"shard\":"
    << json_string(std::to_string(static_cast<int64_t>(id.id.shard)))
    << ",\"seqno\":" << id.id.seqno << ",\"root_hash\":" << json_string(id.root_hash.to_hex())
    << ",\"file_hash\":" << json_string(id.file_hash.to_hex()) << '}';
  return s.str();
}

std::string event_id_json(const events::BlockId& id) {
  std::ostringstream s;
  s << "{\"workchain\":" << id.workchain << ",\"shard\":" << json_string(std::to_string(id.shard))
    << ",\"seqno\":" << id.seqno << ",\"root_hash_b64\":" << json_string(id.root_hash)
    << ",\"file_hash_b64\":" << json_string(id.file_hash) << '}';
  return s.str();
}

const char* classification(events::Classification c) {
  switch (c) {
    case events::Classification::included_wallet: return "included_wallet";
    case events::Classification::excluded_code: return "excluded_code";
    case events::Classification::outside_registry: return "outside_registry";
    default: return "pending";
  }
}

const char* resolution(events::Resolution r) {
  switch (r) {
    case events::Resolution::resolved: return "resolved";
    case events::Resolution::proved_nonexist: return "proved_nonexist";
    case events::Resolution::unsupported: return "unsupported";
    case events::Resolution::replay_error: return "replay_error";
    default: return "unavailable";
  }
}

std::string fact_json(const events::CodeFact& c) {
  std::ostringstream s;
  s << "{\"classification\":" << json_string(classification(c.classification))
    << ",\"resolution\":" << json_string(resolution(c.resolution))
    << ",\"source\":" << json_string(c.source)
    << ",\"code_hash\":" << (c.code_hash_hex ? json_string(*c.code_hash_hex) : "null")
    << ",\"wallet_type\":" << (c.wallet_type_id ? json_string(*c.wallet_type_id) : "null") << '}';
  return s.str();
}

const char* account_status(schema::AccountStatus c) {
  switch (c) {
    case schema::nonexist: return "nonexist";
    case schema::uninit: return "uninit";
    case schema::active: return "active";
    case schema::frozen: return "frozen";
  }
  throw std::runtime_error("unknown native account status");
}

std::string tx_json(const events::TxId& tx) {
  std::ostringstream s;
  s << "{\"account\":" << json_string(tx.account) << ",\"lt\":" << tx.lt
    << ",\"tx_hash\":" << json_string(tx.hash_hex) << ",\"now\":" << tx.now
    << ",\"mc\":" << event_id_json(tx.mc) << ",\"block\":" << event_id_json(tx.shard)
    << ",\"native_pre_state_hash\":" << json_string(tx.pre_state_hash_hex)
    << ",\"native_post_state_hash\":" << json_string(tx.post_state_hash_hex) << '}';
  return s.str();
}

wallets::BlockId stage_id(const ton::BlockIdExt& id) {
  return {id.id.workchain, id.id.shard, id.id.seqno,
          id.root_hash.to_hex(), id.file_hash.to_hex()};
}

struct StageSummary {
  bool independently_checked = false;
  size_t observations = 0;
  size_t unresolved_codes = 0;
  std::string zerostate_proof_id;
  std::string graph_proof_id;
  std::string time_proof_id;
  std::string inventory_proof_id;
  std::string pending_reason = "first MC has no independently verified left tip frontier";
};

StageSummary check_second_anchor(const WalletCliOptions& opts, const ton::BlockIdExt& zero,
                                 const Anchor& anchor, const ton::BlockIdExt& predecessor,
                                 const SourceInventory& source, const events::Batch& batch) {
  stage::VerifiedEnvelope proof;
  proof.scope = {opts.network, opts.zerostate_root, opts.zerostate_file,
                 pilot::kCalcVersion, events::kRegistrySha256, {}};
  for (const auto& tip : anchor.tip_ids) {
    require(tip.id.workchain == 0, "non-basechain tip outside requested scope");
    proof.scope.workchains.insert(tip.id.workchain);
  }
  proof.zerostate_mc = stage_id(zero);
  proof.zerostate_anchor_verified = true; // archived MC0 handle checked against BOTH explicit hashes
  proof.zerostate_anchor_attestation = "wallets:archived-MC0-root+file:" + zero.root_hash.to_hex();
  proof.mc = stage_id(anchor.mc);
  proof.prev_mc = stage_id(predecessor);
  proof.mc_utime = anchor.header_times.at(anchor.mc);
  for (const auto& [id, time] : anchor.tip_times) {
    proof.current_shard_tips.push_back({stage_id(id), time});
  }
  for (const auto& [id, predecessors] : anchor.header_predecessors) {
    if (id.is_masterchain()) continue;
    require(id.id.workchain == 0, "non-basechain included block outside requested scope");
    wallets::CoveredBlock block;
    block.id = stage_id(id);
    block.gen_utime = anchor.header_times.at(id);
    for (const auto& previous : predecessors) block.predecessors.push_back(stage_id(previous));
    proof.first_included_shards.push_back(std::move(block));
  }
  for (const auto& block : source.blocks) proof.raw_blocks.push_back(block.inventory);
  proof.graph_diff_verified = true; // verify_pair: MC typed + raw headers vs full tip frontier
  proof.time_rules_verified = true; // verify_pair + raw::build tx.now == raw BlockInfo.gen_utime
  proof.raw_inventory_verified = true; // raw::build + compare_parsed, independent of events::Batch
  const auto hash = anchor.mc.root_hash.to_hex();
  proof.graph_diff_attestation = "wallets:raw-header-tip-frontier:" + hash;
  proof.time_rules_attestation = "wallets:raw-block-info-time-dag:" + hash;
  proof.raw_inventory_attestation = "wallets:raw-TLB-HASH_UPDATE-outmsgs:" + hash;
  auto envelope = stage::build(proof, batch,
                               {opts.max_blocks, opts.max_tip_roots, opts.max_transactions});
  StageSummary summary;
  summary.independently_checked = true;
  summary.zerostate_proof_id = proof.zerostate_anchor_attestation;
  summary.graph_proof_id = proof.graph_diff_attestation;
  summary.time_proof_id = proof.time_rules_attestation;
  summary.inventory_proof_id = proof.raw_inventory_attestation;
  summary.observations = envelope.observations.size();
  for (const auto& observation : envelope.observations) {
    if (observation.activation_code.kind == wallets::EvidenceKind::unknown ||
        observation.execution_code.kind == wallets::EvidenceKind::unknown) ++summary.unresolved_codes;
  }
  // No genesis baseline and no independently certified event left checkpoint.
  wallets::WalletMetrics reducer(proof.scope, 2, opts.max_transactions);
  reducer.put(std::move(envelope));
  const auto day = reducer.day(proof.mc_utime - proof.mc_utime % 86400);
  require(!day.daily_activations && !day.cumulative_activations && !day.dau &&
          !day.mau_30d && !reducer.contiguous_watermark() && !reducer.event_watermark(),
          "two-MC reducer unexpectedly claimed day or lifetime completeness");
  summary.pending_reason = "two MCs have no lifetime baseline, event left frontier or physical writer";
  return summary;
}

std::string render(const WalletCliOptions& o, const Anchor& a, const ton::BlockIdExt& predecessor,
                    const events::Batch& batch, const SourceInventory& source,
                    const ParsedCounts& parsed, const StageSummary& stage_result,
                    bool mc0_local_verified) {
  std::ostringstream s;
  s << "{\"dataset\":\"wallets\",\"status\":\"pending\",\"network\":" << json_string(o.network)
    << ",\"zerostate_root\":" << json_string(o.zerostate_root)
    << ",\"zerostate_file\":" << json_string(o.zerostate_file)
    << ",\"mc0_local_verified\":" << (mc0_local_verified ? "true" : "false")
    << ",\"network_pin_source\":" << json_string(mc0_local_verified ? "local_mc0_handle" : "external")
    << ",\"calc_version\":" << json_string(pilot::kCalcVersion)
    << ",\"registry_sha256\":" << json_string(batch.registry_sha256)
    << ",\"scope\":" << json_string(o.scope == ton_analytics::wallets::cli::Scope::masterchain_only ? "mc-only" : "mc-and-basechain")
    << ",\"mc\":" << id_json(a.mc) << ",\"predecessor_mc\":" << id_json(predecessor)
    << ",\"raw_transactions\":" << source.transactions
    << ",\"parsed_transactions\":" << parsed.transactions
    << ",\"raw_accounts\":" << source.accounts
    << ",\"parsed_post_accounts\":" << parsed.post_accounts
    << ",\"raw_out_messages\":" << source.out_messages
    << ",\"parsed_out_messages\":" << parsed.out_messages
    << ",\"raw_cell_references\":" << source.cell_references
    << ",\"included_blocks\":[";
  for (size_t i = 0; i < batch.included_blocks.size(); ++i) {
    if (i) s << ',';
    s << event_id_json(batch.included_blocks[i]);
  }
  s << "],\"source_included_blocks\":[";
  for (size_t j = 0; j < a.data.shard_blocks_diff_.size(); ++j) {
    if (j) s << ',';
    s << id_json(a.data.shard_blocks_diff_[j].handle->id());
  }
  s << "],\"shard_tips\":[";
  size_t i = 0;
  for (const auto& tip : a.tip_ids) { if (i++) s << ','; s << id_json(tip); }
  s << "],\"raw_block_inventories\":[";
  for (i = 0; i < source.blocks.size(); ++i) {
    const auto& raw_block = source.blocks[i];
    if (i) s << ',';
    s << "{\"id\":" << id_json(a.data.shard_blocks_diff_[i].handle->id())
      << ",\"accounts\":" << raw_block.account_count
      << ",\"transactions\":" << raw_block.inventory.transactions.size()
      << ",\"out_messages\":" << raw_block.out_message_count
      << ",\"raw_source_proof_id\":" << json_string(raw_block.caller_proof_id) << '}';
  }
  s << "],\"active_witness_total\":" << batch.active_witnesses.size()
    << ",\"qualifying_send_total\":" << batch.sends.size()
    << ",\"pending_post_codes\":" << batch.pending_post_codes
    << ",\"pending_execution_codes\":" << batch.pending_execution_codes
    << ",\"activation_candidate_facts\":[";
  // Emit EVERY per-tx candidate or fail the whole pair on the 1 MB output cap.
  // These are native HASH_UPDATE endpoints checked against raw TL-B before
  // extraction; code facts retain their resolution and evidence source.
  for (i = 0; i < batch.active_witnesses.size(); ++i) {
    const auto& w = batch.active_witnesses[i];
    if (i) s << ',';
    s << "{\"tx\":" << tx_json(w.tx)
      << ",\"orig_status\":" << json_string(account_status(w.orig_status))
      << ",\"end_status\":" << json_string(account_status(w.end_status))
      << ",\"activation_candidate\":" << (w.activation_candidate ? "true" : "false")
      << ",\"post_code\":" << fact_json(w.post_code) << '}';
  }
  s << "],\"qualifying_send_candidate_facts\":[";
  for (i = 0; i < batch.sends.size(); ++i) {
    const auto& w = batch.sends[i];
    if (i) s << ',';
    s << "{\"tx\":" << tx_json(w.tx)
      << ",\"message_hash\":" << json_string(w.message_hash_hex)
      << ",\"execution_code\":" << fact_json(w.execution_code) << '}';
  }
  s << "],\"candidate_facts_truncated\":false,\"address_facts_complete\":false"
    << ",\"stage_build_status\":" << json_string(!mc0_local_verified ? "SKIPPED" :
                                                  stage_result.independently_checked ? "checked" : "not_attempted")
    << ",\"reducer_status\":" << json_string(!mc0_local_verified ? "SKIPPED" :
                                               stage_result.independently_checked ? "diagnostic_pending" : "not_attempted")
    << ",\"stage_input_checked\":" << (stage_result.independently_checked ? "true" : "false")
    << ",\"stage_observations\":" << (stage_result.independently_checked ? std::to_string(stage_result.observations) : "null")
    << ",\"stage_unresolved_codes\":" << (stage_result.independently_checked ? std::to_string(stage_result.unresolved_codes) : "null")
    << ",\"zerostate_proof_id\":" << (stage_result.independently_checked ? json_string(stage_result.zerostate_proof_id) : "null")
    << ",\"graph_proof_id\":" << (stage_result.independently_checked ? json_string(stage_result.graph_proof_id) : "null")
    << ",\"time_proof_id\":" << (stage_result.independently_checked ? json_string(stage_result.time_proof_id) : "null")
    << ",\"inventory_proof_id\":" << (stage_result.independently_checked ? json_string(stage_result.inventory_proof_id) : "null")
    << ",\"stage_pending_reason\":" << json_string(stage_result.pending_reason)
    << pilot::diagnostic_incompleteness_fields() << '}';
  auto output = s.str();
  require(pilot::fits_diagnostic(0, output.size()), "diagnostic JSON exceeds 1 MB cap");
  return output;
}

class CatchUp final : public td::actor::Actor {
 public:
  explicit CatchUp(td::actor::ActorId<DbScanner> scanner) : scanner_(scanner) {}
  void force(td::Promise<td::Unit> p) {
    td::actor::send_closure(scanner_, &DbScanner::request_catch_up, std::move(p),
                            ton::validator::CatchUpMode::Force);
  }
 private:
  td::actor::ActorId<DbScanner> scanner_;
};

td::actor::Task<td::Unit> run(td::actor::ActorId<DbScanner> scanner, td::actor::ActorId<CatchUp> gate,
                              td::actor::ActorId<ParseManager> parser, WalletCliOptions opts,
                              std::shared_ptr<int> exit_code) {
  auto catchup = co_await td::actor::ask(gate, &CatchUp::force).wrap();
  if (catchup.is_error())
    co_return catchup.move_as_error_prefix(pilot::failure_stage_prefix("secondary_catch_up"));
  auto genesis = co_await td::actor::ask(scanner, &DbScanner::get_mc_block_handle, 0).wrap();
  bool mc0_local_verified = false;
  ton::validator::ConstBlockHandle zero;
  if (genesis.is_error()) {
    const auto& error = genesis.error();
    if (!pilot::external_pin_allowed(opts, error.code(), error.message().str()))
      co_return genesis.move_as_error_prefix(pilot::failure_stage_prefix("zerostate_handle_seqno_0"));
    // MC0 was NOT verified locally. This external network pin can only enable
    // limited candidate diagnostics, never a synthetic zerostate stage proof.
  } else {
    zero = genesis.move_as_ok();
    if (!zero || !zero->id().is_masterchain() || zero->id().id.seqno != 0 ||
        !hex_equal(opts.zerostate_root, zero->id().root_hash.to_hex()) ||
        !hex_equal(opts.zerostate_file, zero->id().file_hash.to_hex()))
      co_return td::Status::Error("zerostate_handle_seqno_0: explicit zerostate root/file do not match archived MC0");
    mc0_local_verified = true;
  }
  auto reader_result = co_await td::actor::ask(scanner, &DbScanner::get_cell_db_reader).wrap();
  if (reader_result.is_error())
    co_return reader_result.move_as_error_prefix(pilot::failure_stage_prefix("cell_reader"));
  auto reader = reader_result.move_as_ok();
  if (!reader) co_return td::Status::Error("cell_reader: secondary cell reader unavailable");
  std::vector<std::string> rows;
  size_t total_output_bytes = 0;
  std::unique_ptr<Anchor> previous;
  size_t total_blocks = 0, total_tips = 0, total_transactions = 0;
  size_t total_accounts = 0, total_out_messages = 0, total_cell_references = 0;
  std::string active_stage;
  try {
    for (auto n : {opts.from, opts.to}) {
      active_stage = pilot::mc_failure_stage("fetch", n);
      auto result = co_await td::actor::ask(scanner, &DbScanner::fetch_seqno, n).wrap();
      if (result.is_error())
        co_return result.move_as_error_prefix(pilot::failure_stage_prefix(active_stage));
      active_stage = pilot::mc_failure_stage("parse", n);
      auto anchor = inspect(result.move_as_ok(), opts, n);
      total_blocks += anchor.data.shard_blocks_diff_.size();
      total_tips += anchor.tip_ids.size();
      require(total_blocks <= opts.max_blocks && total_tips <= opts.max_tip_roots,
              "run-wide block/tip cap exceeded");
      if (previous) verify_pair(*previous, anchor);
      // The first anchor's predecessor is verified from the typed MC state,
      // but its shard coverage is NOT a checkpoint; only the second anchor's
      // independent tip graph is compared to a preceding anchor.
      auto typed_result = ton::validator::create_shard_state(anchor.mc,
                              anchor.data.shard_blocks_.front().block_state);
      require(typed_result.is_ok(), "cannot read MC predecessor from typed state");
      td::Ref<ton::validator::MasterchainState> typed{typed_result.move_as_ok()};
      ton::BlockIdExt predecessor;
      require(typed.not_null() && typed->get_old_mc_block_id(n - 1, predecessor) &&
              predecessor.is_masterchain() && predecessor.id.seqno == n - 1 &&
              anchor.header_predecessors.at(anchor.mc).size() == 1 &&
              anchor.header_predecessors.at(anchor.mc).front() == predecessor,
              "typed MC state disagrees with raw header/handle full-ID predecessor");
      // Decode every first-included block directly from verified raw cells
      // BEFORE ParseQuery; no stage input is copied out of events::Batch.
      auto source = read_source(anchor, opts, total_transactions, total_accounts,
                                total_out_messages, total_cell_references);
      auto parsed_result = co_await td::actor::ask(parser, &ParseManager::parse, n,
                                                   std::move(anchor.data), reader).wrap();
      if (parsed_result.is_error())
        co_return parsed_result.move_as_error_prefix(pilot::failure_stage_prefix(active_stage));
      auto parsed = parsed_result.move_as_ok();
      require(parsed && parsed->blocks_.size() <= opts.max_blocks, "incomplete/over-limit parsed blocks");
      anchor.data = parsed->mc_block_; // keep verified cells alive until extraction returns
      const auto parsed_counts = compare_parsed(*parsed, anchor, source);
      if (opts.scope == ton_analytics::wallets::cli::Scope::masterchain_only) {
        parsed->blocks_.erase(std::remove_if(parsed->blocks_.begin(), parsed->blocks_.end(),
            [](const auto& b) { return b.workchain != -1; }), parsed->blocks_.end());
        parsed->mc_block_.shard_blocks_diff_.erase(
            std::remove_if(parsed->mc_block_.shard_blocks_diff_.begin(),
                parsed->mc_block_.shard_blocks_diff_.end(),
                [](const auto& b) { return !b.handle->id().is_masterchain(); }),
            parsed->mc_block_.shard_blocks_diff_.end());
      }
      auto batch = events::extract(*parsed);
      StageSummary stage_result;
      if (pilot::can_build_stage(mc0_local_verified, opts.scope, previous != nullptr)) {
        stage_result = check_second_anchor(opts, zero->id(), anchor, predecessor, source, batch);
      } else if (!mc0_local_verified) {
        stage_result.pending_reason =
            "SKIPPED: MC0 unavailable locally; external network pin is not a zerostate proof; stage and reducer not called";
      } else if (opts.scope == ton_analytics::wallets::cli::Scope::masterchain_only) {
        stage_result.pending_reason = "MC-only scope has no complete basechain stage input";
      }
      auto row = render(opts, anchor, predecessor, batch, source, parsed_counts, stage_result,
                        mc0_local_verified);
      require(pilot::fits_diagnostic(total_output_bytes, row.size()),
              "run-wide diagnostic NDJSON exceeds 1 MB cap");
      total_output_bytes += row.size() + 1;
      rows.push_back(std::move(row));
      previous = std::make_unique<Anchor>(std::move(anchor));
    }
  } catch (const vm::VmError& e) {
    co_return e.as_status("wallets: ").move_as_error_prefix(pilot::failure_stage_prefix(active_stage));
  } catch (const std::exception& e) {
    co_return td::Status::Error(td::Slice(e.what())).move_as_error_prefix(
        pilot::failure_stage_prefix(active_stage));
  }
  for (const auto& row : rows) std::cout << row << '\n';
  *exit_code = 0; // diagnostic ONLY; JSON flags always false
  co_return td::Unit();
}
} // namespace
#endif

int main(int argc, char** argv) {
  try {
    auto opts = ton_analytics::wallets::cli::parse_cli(
        std::vector<std::string>(argv + 1, argv + argc));
#if defined(TON_WALLETS_SECONDARY_SAFETY_REVIEWED) && TON_WALLETS_SECONDARY_SAFETY_REVIEWED == 1
    constexpr bool reviewed = true;
#else
    constexpr bool reviewed = false;
#endif
#if defined(TON_WALLETS_TON_ADAPTER_AVAILABLE) && TON_WALLETS_TON_ADAPTER_AVAILABLE == 1
    constexpr bool adapter = true;
#else
    constexpr bool adapter = false;
#endif
    ton_analytics::wallets::pilot::require_review(reviewed, adapter);
#if defined(TON_WALLETS_TON_ADAPTER_AVAILABLE) && TON_WALLETS_TON_ADAPTER_AVAILABLE == 1
    limit_process(); // before any DB open
    ton_analytics::wallets::pilot::revalidate_paths(opts);
    SET_VERBOSITY_LEVEL(verbosity_WARNING);
    td::actor::Scheduler scheduler({2});
    td::actor::ActorOwn<DbScanner> scanner;
    td::actor::ActorOwn<CatchUp> gate;
    td::actor::ActorOwn<ParseManager> parser;
    auto exit_code = std::make_shared<int>(1);
    auto watcher = td::create_shared_destructor([] { td::actor::SchedulerContext::get().stop(); });
    scheduler.run_in_context([&, watcher = std::move(watcher)]() mutable {
      scanner = td::actor::create_actor<DbScanner>("wallets-secondary", opts.db_root.string(),
                   dbs_secondary, opts.secondary_work_dir.string(), 3600.0f, false);
      gate = td::actor::create_actor<CatchUp>("wallets-catchup", scanner.get());
      parser = td::actor::create_actor<ParseManager>("wallets-parser");
      auto finished = td::PromiseCreator::lambda([watcher = std::move(watcher), exit_code](td::Result<td::Unit> result) {
        if (result.is_error()) {
          std::cerr << "wallets pending: " << result.move_as_error().to_string() << '\n';
          *exit_code = 1;
        }
      });
      td::connect(std::move(finished), run(scanner.get(), gate.get(), parser.get(), opts, exit_code).start());
    });
    scheduler.run();
    return *exit_code;
#endif
  } catch (const std::exception& e) {
    std::cerr << "ton-analytics-wallets: " << e.what() << '\n';
    return 2;
  }
  return 2; // offline build can NEVER open NodeDB
}
