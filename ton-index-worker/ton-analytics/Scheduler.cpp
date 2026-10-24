#include "Scheduler.h"
#include "Adapters.h"
#include "Frontier.h"
#include "../ton-analytics-gram/record.h"
#include "crypto/block/block-auto.h"
#include "crypto/block/block-parse.h"
#include "crypto/block/mc-config.h"
#include "validator/fabric.h"
#include "validator/global-balance-calculator.hpp"
#include <iostream>
#include <map>
#include <set>

namespace tonstat::runner {
namespace {
using ton::BlockIdExt;
using ton::validator::MasterchainState;
template <class T> T required(td::Result<T> result, const std::string& reason) {
  if (result.is_error()) throw std::runtime_error(reason + ": " + result.move_as_error().to_string());
  return result.move_as_ok();
}
td::Ref<MasterchainState> typed_mc(const schema::BlockDataState& entry) {
  auto raw = required(ton::validator::create_shard_state(entry.handle->id(), entry.block_state), "typed MC");
  td::Ref<MasterchainState> mc{raw}; require(mc.not_null(), "state is not MC"); return mc;
}
void require_evidence(const std::shared_ptr<const core::AnchorEvidence>& e, const Options& o) {
  std::string why;
  if (e) for (const auto& issue : e->issues) why += issue.code + ":" + issue.detail + "; ";
  require(e && e->status == core::Status::verified_local_archive, "archive verification failed: " + why);
  require(e->network == o.network, "raw global ID does not match requested network");
}
std::set<BlockIdExt> tip_set(const schema::BlockDataState& mc) {
  block::gen::ShardStateUnsplit::Record state;
  block::gen::McStateExtra::Record extra;
  require(tlb::unpack_cell(mc.block_state, state) && state.custom.not_null() &&
      tlb::unpack_cell(state.custom->prefetch_ref(), extra) &&
      block::gen::t_ShardHashes.validate_csr(1 << 20, extra.shard_hashes), "malformed previous/current ShardHashes");
  std::set<BlockIdExt> out;
  for (const auto& desc : typed_mc(mc)->get_shards())
    require(out.insert(desc->top_block_id()).second, "duplicate MC shard tip");
  return out;
}
// Uses raw block predecessor full IDs, not handle.prev. Every frontier leaf is
// accounted for. No missing block can be replaced by an unchanged/repeated tip.
void verify_frontier(const core::MaterializedAnchor& view, const schema::BlockDataState& prev, size_t limit) {
  auto old = tip_set(prev), expected = tip_set(view.mc());
  old.insert(prev.handle->id()); expected.insert(view.evidence().mc.id);
  std::set<BlockIdExt> included;
  std::map<BlockIdExt, std::vector<BlockIdExt>> pending;
  std::map<BlockIdExt, std::vector<BlockIdExt>> children;
  require(view.first_included().size() <= limit, "frontier block limit exceeded");
  for (const auto& entry : view.first_included()) {
    const auto id = entry.handle->id();
    require(!old.count(id) && included.insert(id).second, "repeated tip/duplicate in first-included blocks");
    auto h = required(block::get_block_header_info(entry.block_data->root_cell(), id), "raw block predecessor");
    require(!h.prev.empty() && h.prev.size() <= 2, "invalid predecessor arity");
    std::set<BlockIdExt> distinct;
    for (const auto& p : h.prev) {
      require(p.is_valid_full() && p.id.workchain == id.id.workchain && p.id.seqno < id.id.seqno && distinct.insert(p).second,
              "invalid/duplicate predecessor ID");
      children[p].push_back(id);
    }
    if (id.is_masterchain()) require(h.prev.size() == 1 && h.prev.front() == prev.handle->id(), "MC predecessor mismatch");
    else if (h.prev.size() == 2) {
      require(!h.after_split && ton::shard_is_parent(id.id.shard, h.prev[0].id.shard) &&
          ton::shard_is_parent(id.id.shard, h.prev[1].id.shard) && ton::shard_is_sibling(h.prev[0].id.shard, h.prev[1].id.shard),
          "invalid raw merge topology");
    } else require(h.after_split ? ton::shard_is_parent(h.prev[0].id.shard, id.id.shard) : h.prev[0].id.shard == id.id.shard,
                   "invalid raw split/ordinary topology");
    pending.emplace(id, std::move(h.prev));
  }
  for (const auto& [parent, kids] : children) if (kids.size() > 1)
    require(kids.size() == 2 && ton::shard_is_parent(parent.id.shard, kids[0].id.shard) &&
        ton::shard_is_parent(parent.id.shard, kids[1].id.shard) && ton::shard_is_sibling(kids[0].id.shard, kids[1].id.shard),
        "invalid branch/duplicate split child");
  require_frontier(old, expected, std::move(pending));
}
td::actor::Task<schema::BlockDataState> load_aux(td::actor::ActorId<DbScanner> scanner, BlockIdExt id,
                                                core::NetworkPin pin, const Options& o) {
  auto r = co_await td::actor::ask(scanner, &DbScanner::fetch_block_by_id, id).wrap();
  if (r.is_error()) co_return r.move_as_error();
  auto entry = r.move_as_ok();
  try { require_evidence(core::verify_auxiliary_mc(entry, id, pin), o); }
  catch (const std::exception& e) { co_return td::Status::Error(td::Slice(e.what())); }
  co_return entry;
}
void require_ancestor(const td::Ref<MasterchainState>& mc, const BlockIdExt& id) {
  BlockIdExt actual;
  require(id.is_masterchain() && id.id.seqno < mc->get_block_id().id.seqno &&
      mc->get_old_mc_block_id(id.id.seqno, actual) && actual == id, "historical MC reference not in anchor ancestry dictionary");
}
td::actor::Task<std::map<BlockIdExt, ConfigSource>> configs(td::actor::ActorId<DbScanner> scanner,
    std::shared_ptr<const core::MaterializedAnchor> view, const schema::BlockDataState& previous,
    core::NetworkPin pin, const Options& o) {
  try {
  std::map<BlockIdExt, ConfigSource> result, by_mc;
  auto mc = typed_mc(view->mc());
  for (const auto& entry : view->first_included()) {
    auto id = entry.handle->id();
    auto h = required(block::get_block_header_info(entry.block_data->root_cell(), id), "execution MC reference");
    auto ref = h.mc_blkid;
    // For an MC block this is its predecessor; for a shard it is its raw
    // master_ref (which may lag the including MC by many blocks/key changes).
    require_ancestor(mc, ref);
    if (!by_mc.count(ref)) {
      require(by_mc.size() < o.max_aux, "historical config MC read cap exceeded");
      schema::BlockDataState source;
      if (ref == previous.handle->id()) source = previous;
      else {
        auto r = co_await load_aux(scanner, ref, pin, o).wrap();
        if (r.is_error()) co_return r.move_as_error();
        source = r.move_as_ok();
      }
      auto cfg = required(block::ConfigInfo::extract_config(source.block_state, ref, block::ConfigInfo::needCapabilities), "historical config");
      auto eight = cfg->get_config_param(8);
      require(eight.not_null() && cfg->get_global_version() >= 0, "historical config8 unavailable");
      by_mc.emplace(ref, ConfigSource{ref, source.block_state->get_hash().as_bits256(), eight->get_hash().as_bits256(),
                                     static_cast<uint32_t>(cfg->get_global_version())});
    }
    result.emplace(id, by_mc.at(ref));
  }
  co_return result;
  } catch (const vm::VmError& e) { co_return e.as_status("historical config: "); }
  catch (const std::exception& e) { co_return td::Status::Error(td::Slice(e.what())); }
}
td::actor::Task<ton::validator::GlobalBalanceComponents> balance(td::actor::ActorId<DbScanner> scanner,
    std::shared_ptr<const core::MaterializedAnchor> view, core::NetworkPin pin, const Options& o) {
  try {
  auto mc = typed_mc(view->mc());
  std::vector<ton::validator::GlobalBalanceShardState> shards;
  for (size_t i = 1; i < view->snapshot().shard_blocks_.size(); ++i) {
    const auto& e = view->snapshot().shard_blocks_[i];
    shards.push_back({required(ton::validator::create_shard_state(e.handle->id(), e.block_state), "Supply shard state"), e.block_data->root_cell()});
  }
  auto count = std::make_shared<size_t>(0);
  auto aux = [scanner, pin, &o, count, mc, view](BlockIdExt id) -> td::actor::Task<td::Ref<MasterchainState>> {
    // Keep view/reader in the callback lease as well as in this coroutine.
    (void)view;
    if (++*count > o.max_aux) co_return td::Status::Error("Supply auxiliary MC read cap exceeded");
    try { require_ancestor(mc, id); } catch (const std::exception& e) { co_return td::Status::Error(td::Slice(e.what())); }
    auto loaded = co_await load_aux(scanner, id, pin, o).wrap();
    if (loaded.is_error()) co_return loaded.move_as_error();
    try { co_return typed_mc(loaded.move_as_ok()); }
    catch (const std::exception& e) { co_return td::Status::Error(td::Slice(e.what())); }
  };
  auto r = co_await ton::validator::calculate_global_balance_at_anchor(mc, view->mc().block_data->root_cell(), std::move(shards), aux).wrap();
  if (r.is_error()) co_return r.move_as_error();
  auto b = r.move_as_ok();
  for (auto amount : {b.accounts, b.dispatch_queue, b.unprocessed_messages, b.unrecovered_validator_fees, b.total, b.burned})
    require(amount.not_null() && amount->is_valid() && td::sgn(amount) >= 0, "invalid Supply component");
  require(b.total == b.accounts + b.dispatch_queue + b.unprocessed_messages + b.unrecovered_validator_fees,
          "Supply components do not sum to total");
  co_return b;
  } catch (const vm::VmError& e) { co_return e.as_status("Supply: "); }
  catch (const std::exception& e) { co_return td::Status::Error(td::Slice(e.what())); }
}
std::string money_json(const ton::validator::GlobalBalanceComponents& b) {
  return "{\"accounts\":" + gram::amount(b.accounts) + ",\"dispatch_queue\":" + gram::amount(b.dispatch_queue) +
      ",\"unprocessed_messages\":" + gram::amount(b.unprocessed_messages) + ",\"unrecovered_validator_fees\":" + gram::amount(b.unrecovered_validator_fees) +
      ",\"total\":" + gram::amount(b.total) + ",\"burned\":" + gram::amount(b.burned) + "}";
}
// Same config14 transition count as the read-only Supply API/Gram target,
// additionally checked against the independently exhaustive raw diff.
td::RefInt256 issuance(const schema::BlockDataState& prev, const core::MaterializedAnchor& current, size_t actual_count) {
  auto cfg = required(block::ConfigInfo::extract_config(prev.block_state, prev.handle->id(), 0), "preceding config14");
  auto param = cfg->get_config_param(14);
  block::gen::BlockCreateFees::Record fees;
  td::RefInt256 mc_fee, base_fee;
  require(param.not_null() && tlb::unpack_cell(param, fees) && block::tlb::t_Grams.as_integer_to(fees.masterchain_block_fee, mc_fee) &&
      block::tlb::t_Grams.as_integer_to(fees.basechain_block_fee, base_fee), "invalid preceding config14");
  auto old = typed_mc(prev), next = typed_mc(current.mc());
  auto sum = mc_fee; uint64_t count = 1;
  for (const auto& desc : next->get_shards()) {
    auto left = old->get_shard_from_config(desc->shard() - 1, false), right = old->get_shard_from_config(desc->shard() + 1, false);
    require(left.is_null() == right.is_null(), "inconsistent previous Supply shard config");
    int64_t n = 0;
    if (left.not_null()) {
      if (left->shard() == desc->shard()) n = left->top_block_id().seqno();
      else if (left->shard() == right->shard()) {
        require(desc->shard().pfx_len() > 0 && left->shard() == ton::shard_parent(desc->shard()), "invalid Supply split");
        n = left->top_block_id().seqno();
      } else {
        require(left->shard() == ton::shard_child(desc->shard(), true) && right->shard() == ton::shard_child(desc->shard(), false), "invalid Supply merge");
        n = std::max(left->top_block_id().seqno(), right->top_block_id().seqno());
      }
    }
    n = static_cast<int64_t>(desc->top_block_id().seqno()) - n; require(n >= 0, "Supply shard sequence regressed");
    sum += (base_fee >> ton::shard_prefix_length(desc->shard())) * n; count += n;
  }
  require(count == actual_count && sum->is_valid(), "Supply issuance coverage/count mismatch");
  return sum;
}
} // namespace

td::actor::Task<td::Unit> run(td::actor::ActorId<DbScanner> scanner, td::actor::ActorId<CatchUp> catchup,
                            td::actor::ActorId<ParseManager> parser, Options o, Progress& progress) {
  auto caught = co_await td::actor::ask(catchup, &CatchUp::once).wrap();
  if (caught.is_error()) co_return caught.move_as_error();
  core::NetworkPin pin{{ton::masterchainId, ton::shardIdAll, 0, bits(o.zero_root), bits(o.zero_file)}};
  auto zero = co_await td::actor::ask(scanner, &DbScanner::get_mc_block_handle, 0).wrap();
  if (zero.is_error()) co_return zero.move_as_error();
  auto zh = zero.move_as_ok();
  if (!zh || zh->id() != pin.zerostate) co_return td::Status::Error("pinned zerostate differs from archived MC0 handle");
  auto reader_result = co_await td::actor::ask(scanner, &DbScanner::get_cell_db_reader).wrap();
  if (reader_result.is_error()) co_return reader_result.move_as_error();
  auto reader = reader_result.move_as_ok();
  if (!reader) co_return td::Status::Error("secondary CellDbReader unavailable");
  for (const auto& request : o.anchors) {
    std::unique_ptr<Rows> rows;
    std::unique_ptr<Rows> snapshot_rows;
    auto save_failure = [&](const std::string& reason) {
      if (!snapshot_rows) return;
      snapshot_rows->add("anchor_failure", std::to_string(request.seqno), "error",
          "{\"anchor_committed\":false,\"event_range_complete\":false,\"reason\":" + quote(reason) + "}");
      progress.failed(request.seqno, snapshot_rows->text());
    };
    try {
      auto hr = co_await td::actor::ask(scanner, &DbScanner::get_mc_block_handle, request.seqno).wrap();
      if (hr.is_error()) throw std::runtime_error(hr.move_as_error().to_string());
      auto handle = hr.move_as_ok(); require(bool(handle), "missing selected MC handle");
      const auto id = handle->id();
      require(id.is_masterchain() && id.id.seqno == request.seqno, "wrong selected MC ID");
      require(request.root.empty() || (lower(id.root_hash.to_hex()) == request.root && lower(id.file_hash.to_hex()) == request.file),
              "selected MC differs from explicit full anchor ID");
      if (progress.completed(request.seqno, id.to_str())) continue;
      // Read MC alone first: snapshot-only validators survive an event dependency failure.
      auto mr = co_await load_aux(scanner, id, pin, o).wrap();
      if (mr.is_error()) throw std::runtime_error(mr.move_as_error().to_string());
      auto mc = mr.move_as_ok();
      auto aux_evidence = core::verify_auxiliary_mc(mc, id, pin); require_evidence(aux_evidence, o);
      require(aux_evidence->mc.gen_utime >= o.anchor_time_from && aux_evidence->mc.gen_utime < o.anchor_time_to,
              "anchor time lies outside requested UTC interval");
      rows = std::make_unique<Rows>(o, progress.scope_id(), *aux_evidence);
      schema::MasterchainBlockDataState mc_only; mc_only.shard_blocks_.push_back(mc);
      auto validator_error = validators(*rows, mc_only, *aux_evidence);
      snapshot_rows = std::make_unique<Rows>(*rows);
      require(validator_error.empty(), validator_error);

      require(aux_evidence->mc_predecessors.size() == 1, "missing raw MC predecessor");
      auto previous_id = aux_evidence->mc_predecessors.front();
      auto pr = co_await load_aux(scanner, previous_id, pin, o).wrap();
      if (pr.is_error()) throw std::runtime_error(pr.move_as_error().to_string());
      auto previous = pr.move_as_ok();
      auto fetched = co_await td::actor::ask(scanner, &DbScanner::fetch_seqno, request.seqno).wrap();
      if (fetched.is_error()) throw std::runtime_error(fetched.move_as_error().to_string());
      auto data = fetched.move_as_ok();
      require(data.shard_blocks_.size() <= o.max_blocks && data.shard_blocks_diff_.size() <= o.max_blocks, "scanner snapshot exceeds block cap");
      // Zero-seqno shard state is not an ordinary block. Do not synthesize a
      // BoC/state_update proof or silently drop it; Core fails this scope closed.
      auto verified = core::verify_anchor(data, id, pin, {}, &previous, reader);
      require_evidence(verified.evidence, o); require(bool(verified.view), "Core did not return retained reader view");
      auto view = verified.view;
      require(view->evidence().snapshot_integrity_checked &&
          view->evidence().continuity_status == core::Status::verified_local_archive, "MC snapshot/continuity not verified");
      verify_frontier(*view, previous, o.max_blocks);
      auto context = co_await configs(scanner, view, previous, pin, o).wrap();
      if (context.is_error()) throw std::runtime_error(context.move_as_error().to_string());
      auto applied = context.move_as_ok();
      ton_analytics::flow::Limits limits;
      limits.max_blocks = o.max_blocks; limits.max_transactions_per_block = o.max_transactions;
      limits.max_accounts_per_block = o.max_transactions; limits.max_messages_per_block = o.max_transactions * 256ULL;
      limits.max_zero_sink_sends_per_batch = o.max_transactions;
      auto flow = ton_analytics::flow::extract(view->snapshot(), [&](const auto& b) -> std::optional<uint32_t> {
        auto it = applied.find(native_id(b)); return it == applied.end() ? std::nullopt : std::make_optional(it->second.version);
      }, limits);
      uint64_t txs = 0; for (const auto& b : flow.blocks) txs += b.tx_count;
      require(txs <= o.max_transactions, "per-anchor transaction limit exceeded");
      rows = std::make_unique<Rows>(o, progress.scope_id(), view->evidence());
      rows->anchor(view->evidence(), true);
      validator_error = validators(*rows, view->snapshot(), view->evidence(), &previous);
      require(validator_error.empty(), validator_error);
      rows->flow(flow, applied);
      accounts_sample(*rows, *view, o);
      if (o.wallet_events || o.nft_candidates) {
        auto parsed = co_await td::actor::ask(parser, &ParseManager::parse, request.seqno, view->snapshot(), reader).wrap();
        if (parsed.is_error()) throw std::runtime_error(parsed.move_as_error().to_string());
        auto p = parsed.move_as_ok(); require(bool(p), "parser returned null"); parsed_events(*rows, *p, flow, o);
      }
      if (o.supply) {
        // At most two full anchors are retained. The prior snapshot is released
        // immediately after this transition; never buffer the requested month.
        auto old_data = co_await td::actor::ask(scanner, &DbScanner::fetch_seqno, previous_id.id.seqno).wrap();
        if (old_data.is_error()) throw std::runtime_error(old_data.move_as_error().to_string());
        auto old_verified = core::verify_anchor(old_data.move_as_ok(), previous_id, pin, {}, nullptr, reader);
        require_evidence(old_verified.evidence, o); require(bool(old_verified.view), "Supply prior reader lease missing");
        auto old_balance = co_await balance(scanner, old_verified.view, pin, o).wrap();
        if (old_balance.is_error()) throw std::runtime_error(old_balance.move_as_error().to_string());
        auto before = old_balance.move_as_ok();
        old_verified.view.reset();
        auto new_balance = co_await balance(scanner, view, pin, o).wrap();
        if (new_balance.is_error()) throw std::runtime_error(new_balance.move_as_error().to_string());
        auto after = new_balance.move_as_ok();
        auto created = issuance(previous, *view, flow.blocks.size());
        auto raw_created = td::zero_refint();
        for (const auto& b : flow.blocks) {
          auto n = td::dec_string_to_int256(b.created_nanoton); require(n.not_null() && n->is_valid(), "invalid raw created"); raw_created += n;
          require(b.minted_grams_nanoton == "0", "unexpected nonzero minted grams");
        }
        require(raw_created == created, "raw ValueFlow.created differs from config14 issuance");
        auto residual = gram::residual(before.total, after.total, created, after.burned);
        require(residual->is_valid() && residual == td::zero_refint(), "nonzero Supply residual; anchor not committed");
        rows->add("supply_transition", id.to_str(), "verified_local_archive",
            "{\"calculator\":\"calculate_global_balance_at_anchor\",\"previous_mc\":" + id_json(previous_id) +
            ",\"previous_state_root\":" + quote(lower(previous.block_state->get_hash().to_hex())) +
            ",\"before_nanoton\":" + money_json(before) + ",\"after_nanoton\":" + money_json(after) +
            ",\"created_nanoton\":" + gram::amount(created) + ",\"residual_nanoton\":" + gram::amount(residual) + "}");
      }
      Commit commit{request.seqno, id.to_str(), {}, rows->text()};
      for (const auto& b : flow.blocks) commit.block_coordinates.push_back(coordinate(native_id(b.id)));
      progress.commit(commit);
      std::cerr << "committed MC " << request.seqno << ": " << flow.blocks.size() << " blocks, " << txs << " transactions\n";
    } catch (const vm::VmError& e) {
      auto message = std::string(e.get_msg());
      save_failure(message);
      co_return td::Status::Error("MC " + std::to_string(request.seqno) + ": " + message);
    } catch (const std::exception& e) {
      save_failure(e.what());
      co_return td::Status::Error("MC " + std::to_string(request.seqno) + ": " + e.what());
    }
  }
  co_return td::Unit();
}
} // namespace tonstat::runner
