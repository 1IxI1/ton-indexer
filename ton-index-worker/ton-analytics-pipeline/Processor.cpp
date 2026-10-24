#include "Processor.h"
#include "../ton-analytics/Adapters.h"
#include "../ton-analytics/Frontier.h"
#include "../ton-analytics-wallets/WalletRawInventory.h"
#include "../ton-analytics-assets/AssetFacts.h"
#include "../tondb-scanner/src/assets_analytics/Extractor.h"
#include "../tondb-scanner/src/assets_analytics/NftEvents.h"
#include "crypto/block/block-auto.h"
#include "crypto/block/block-parse.h"
#include "crypto/block/mc-config.h"
#include "td/utils/crypto.h"
#include "common/checksum.h"
#include <set>

namespace tonstat::pipeline {
namespace {
using namespace runner;
namespace w = ton_analytics::wallets;
template<class T> T need(td::Result<T> r) {
  if (r.is_error()) throw std::runtime_error(r.move_as_error().to_string());
  return r.move_as_ok();
}
std::string issues(const core::AnchorEvidence& e) {
  std::string s;
  for (const auto& i : e.issues) s += i.code + ":" + i.detail + "; ";
  return s;
}
w::BlockId wallet_id(const ton::BlockIdExt& id) {
  return {id.id.workchain,id.id.shard,id.id.seqno,lower(id.root_hash.to_hex()),lower(id.file_hash.to_hex())};
}
template<class B> ton::BlockIdExt parsed_id(const B& b) {
  auto hash = [](const std::string& h) {
    auto s = need(td::base64_decode(h)); require(s.size() == 32, "invalid parsed full ID");
    td::Bits256 out; out.as_slice().copy_from(s); return out;
  };
  return {b.workchain,static_cast<uint64_t>(b.shard),b.seqno,hash(b.root_hash),hash(b.file_hash)};
}

// This extracts provenance, not a substitute Core success attestation. Local
// BoC/root/update and native global ID checks allow pending facts to be spooled
// even when Core lacks historical context. Its failure/status stays unchanged.
core::AnchorEvidence metadata(const schema::BlockDataState& mc, const core::NetworkPin& pin) {
  require(mc.handle && mc.block_data.not_null() && mc.block_state.not_null(), "missing raw MC input");
  const auto id = mc.handle->id();
  require(id.is_masterchain() && id.is_valid_full() && id.seqno() > 0 && mc.block_data->block_id() == id,
          "wrong MC full ID");
  require(td::sha256_bits256(mc.block_data->data().as_slice()) == id.file_hash &&
          mc.block_data->root_cell()->get_hash().as_bits256() == id.root_hash, "MC original BoC/root hash mismatch");
  block::gen::Block::Record raw; block::gen::BlockInfo::Record info;
  require(tlb::unpack_cell(mc.block_data->root_cell(),raw) && tlb::unpack_cell(raw.info,info), "malformed raw MC");
  auto header = need(block::get_block_header_info(mc.block_data->root_cell(),id));
  auto hashes = core::testing::state_update_hashes(raw.state_update);
  require(hashes.second == mc.block_state->get_hash().as_bits256(), "MC state_update mismatch");
  auto trusted = core::testing::trusted_mc0(raw.global_id);
  require(trusted && *trusted == pin.zerostate, "native raw global ID differs from pinned network");
  require(header.prev.size() == 1 && header.prev.front().is_valid_full() && header.prev.front().is_masterchain(), "invalid raw MC predecessor");
  auto e = *core::verify_auxiliary_mc(mc,id,pin);
  e.mc = {id,mc.block_state->get_hash().as_bits256(),hashes.first,hashes.second,raw.global_id,info.gen_utime};
  e.mc_predecessors = header.prev;
  e.network = raw.global_id == -239 ? "mainnet" : "testnet";
  return e;
}

// The domain stage requires an independently verified complete tip transition.
// Compare raw full predecessors, split/merge shape, reachability and times against
// the PREVIOUS verified snapshot; no boolean derived from parser event counts.
void frontier(const core::AnchorEvidence& current, const core::AnchorEvidence& prior,
              const schema::MasterchainBlockDataState& input) {
  require(current.status == core::Status::verified_local_archive && current.snapshot_integrity_checked &&
          prior.status == core::Status::verified_local_archive && prior.snapshot_integrity_checked &&
          current.continuity_status == core::Status::verified_local_archive &&
          current.previous_mc == prior.mc.id, "adjacent verified full snapshots unavailable");
  std::set<ton::BlockIdExt> old{prior.mc.id}, expected{current.mc.id};
  std::map<ton::BlockIdExt,uint32_t> times{{prior.mc.id,prior.mc.gen_utime},{current.mc.id,current.mc.gen_utime}};
  for (const auto& tip : prior.shard_tips) { old.insert(tip.id); times[tip.id] = tip.gen_utime; }
  for (const auto& tip : current.shard_tips) expected.insert(tip.id);
  for (const auto& b : current.first_included) times[b.id] = b.gen_utime;
  std::map<ton::BlockIdExt,std::vector<ton::BlockIdExt>> graph, children;
  for (const auto& b : input.shard_blocks_diff_) {
    const auto id = b.handle->id();
    auto h = need(block::get_block_header_info(b.block_data->root_cell(),id));
    require(!h.prev.empty() && h.prev.size() <= 2, "invalid predecessor arity");
    if (id.is_masterchain()) require(h.prev.size() == 1 && h.prev.front() == prior.mc.id, "MC predecessor mismatch");
    else if (h.prev.size() == 2)
      require(!h.after_split && ton::shard_is_parent(id.id.shard,h.prev[0].id.shard) &&
              ton::shard_is_parent(id.id.shard,h.prev[1].id.shard) &&
              ton::shard_is_sibling(h.prev[0].id.shard,h.prev[1].id.shard), "invalid raw merge");
    else require(h.after_split ? ton::shard_is_parent(h.prev[0].id.shard,id.id.shard) : h.prev[0].id.shard == id.id.shard,
                 "invalid raw split/ordinary edge");
    for (const auto& p : h.prev) {
      require(p.is_valid_full() && p.id.workchain == id.id.workchain && p.seqno() < id.seqno() &&
              times.count(p) && times.at(p) <= times.at(id), "missing/nonmonotonic raw predecessor");
      children[p].push_back(id);
    }
    require(times.at(id) <= current.mc.gen_utime && graph.emplace(id,h.prev).second, "duplicate/future diff block");
  }
  for (const auto& [p,kids] : children) if (kids.size() > 1)
    require(kids.size() == 2 && ton::shard_is_parent(p.id.shard,kids[0].id.shard) &&
            ton::shard_is_parent(p.id.shard,kids[1].id.shard) &&
            ton::shard_is_sibling(kids[0].id.shard,kids[1].id.shard), "invalid split fanout");
  require_frontier(old,expected,std::move(graph));
}

void pending(Rows& rows, const std::string& dataset, const std::string& key, const std::string& reason) {
  rows.add(dataset,key,"pending","{\"value\":null,\"reason\":" + quote(reason) + "}");
}
std::string code(const w::events::CodeFact& c) {
  return "{\"classification\":" + std::to_string(static_cast<int>(c.classification)) +
      ",\"resolution\":" + std::to_string(static_cast<int>(c.resolution)) + ",\"source\":" + quote(c.source) +
      ",\"hash\":" + (c.code_hash_hex ? quote(lower(*c.code_hash_hex)) : "null") +
      ",\"wallet_type\":" + (c.wallet_type_id ? quote(*c.wallet_type_id) : "null") + "}";
}
std::string tx(const w::events::TxId& t) {
  return "\"source_block\":" + id_json(parsed_id(t.shard)) + ",\"account\":" + quote(t.account) +
      ",\"lt\":" + quote(std::to_string(t.lt)) + ",\"tx_hash\":" + quote(lower(t.hash_hex)) +
      ",\"now\":" + std::to_string(t.now) + ",\"utc_day_start\":" + std::to_string(t.utc_day_start) +
      ",\"state_before\":" + quote(lower(t.pre_state_hash_hex)) + ",\"state_after\":" + quote(lower(t.post_state_hash_hex));
}
void wallet_events(Rows& rows, const w::events::Batch& events) {
  for (const auto& a : events.active_witnesses)
    rows.add("wallet_active_witness",a.tx.hash_hex,"observed_not_lifetime_first",
        "{" + tx(a.tx) + ",\"registry_sha256\":" + quote(events.registry_sha256) +
        ",\"activation_candidate\":" + (a.activation_candidate ? "true" : "false") +
        ",\"orig_status\":" + std::to_string(static_cast<int>(a.orig_status)) +
        ",\"end_status\":" + std::to_string(static_cast<int>(a.end_status)) + ",\"post_code\":" + code(a.post_code) + "}");
  for (const auto& s : events.sends)
    rows.add("wallet_qualifying_send",s.tx.hash_hex,"per_code_resolution",
        "{" + tx(s.tx) + ",\"registry_sha256\":" + quote(events.registry_sha256) +
        ",\"message_hash\":" + quote(lower(s.message_hash_hex)) + ",\"execution_code\":" + code(s.execution_code) + "}");
}

void wallet_stage(Rows& rows, const ParsedBlock& parsed, const core::AnchorEvidence& e,
                  const w::events::Batch& events, const Options& o) {
  w::stage::VerifiedEnvelope proof;
  proof.scope = {e.network,lower(e.pin.zerostate.root_hash.to_hex()),lower(e.pin.zerostate.file_hash.to_hex()),
                 "index-pipeline-wallet-v1",events.registry_sha256,{}};
  proof.zerostate_mc = wallet_id(e.pin.zerostate);
  proof.mc = wallet_id(e.mc.id); proof.prev_mc = wallet_id(*e.previous_mc); proof.mc_utime = e.mc.gen_utime;
  // These checks have actually run above. They prove local archive relationships,
  // never consensus signatures, a genesis chain proof, baseline or day closure.
  proof.zerostate_anchor_verified = true;
  proof.zerostate_anchor_attestation = "Core:published-network-pair/native-global-id:" + e.pin.zerostate.to_str();
  proof.graph_diff_verified = proof.time_rules_verified = proof.raw_inventory_verified = true;
  proof.graph_diff_attestation = "raw-predecessor-tip-frontier:" + e.mc.id.to_str();
  proof.time_rules_attestation = "raw-header-time-DAG:" + e.mc.id.to_str();
  proof.raw_inventory_attestation = "raw-TLB-tx-HASH_UPDATE-outmsgs:" + e.mc.id.to_str();
  for (const auto& tip : e.shard_tips) {
    proof.scope.workchains.insert(tip.id.id.workchain);
    proof.current_shard_tips.push_back({wallet_id(tip.id),tip.gen_utime});
  }
  size_t total = 0;
  for (const auto& source : parsed.mc_block_.shard_blocks_diff_) {
    const auto id = source.handle->id();
    auto raw = w::raw_inventory::build(source,{id,true,true,proof.graph_diff_attestation},
        {o.max_transactions,o.max_transactions,500000,2000000});
    total += raw.inventory.transactions.size(); require(total <= o.max_transactions, "wallet raw inventory cap exceeded");
    if (!id.is_masterchain()) {
      auto h = need(block::get_block_header_info(source.block_data->root_cell(),id));
      w::CoveredBlock b; b.id = wallet_id(id); b.gen_utime = raw.inventory.gen_utime;
      for (const auto& p : h.prev) b.predecessors.push_back(wallet_id(p));
      proof.first_included_shards.push_back(std::move(b));
    }
    proof.raw_blocks.push_back(std::move(raw.inventory));
  }
  auto out = w::stage::build(proof,events,{o.max_blocks,o.max_blocks,o.max_transactions});
  rows.add("wallet_stage",e.mc.id.to_str(),"verified_local_inventory",
      "{\"observations\":" + std::to_string(out.observations.size()) +
      ",\"graph_diff_attestation\":" + quote(out.graph_diff_attestation) +
      ",\"time_rules_attestation\":" + quote(out.time_rules_attestation) +
      ",\"tx_inventory_attestation\":" + quote(out.tx_inventory_attestation) +
      ",\"daily_activations\":null,\"dau\":null,\"mau\":null,\"reason\":\"no lifetime baseline or closed UTC-day frontier\"}");
}

void asset_snapshot(Rows& rows, const ParsedBlock& p, const core::AnchorEvidence& e, const Options& o) {
  if (o.asset_wallets.empty()) return;
  require(e.status == core::Status::verified_local_archive && e.snapshot_integrity_checked,
          "Assets snapshot needs verified complete current tips");
  assets_analytics::Anchor anchor;
  anchor.network = e.network; anchor.zerostate = lower(e.pin.zerostate.root_hash.to_hex()); anchor.gen_utime = e.mc.gen_utime;
  anchor.mc = {e.mc.id,e.mc.state_root,p.mc_block_.shard_blocks_.front().block_state,true};
  for (size_t i=1; i<p.mc_block_.shard_blocks_.size(); ++i) {
    const auto& s = p.mc_block_.shard_blocks_[i];
    anchor.shard_tips.push_back({s.handle->id(),s.block_state->get_hash().as_bits256(),s.block_state,true});
  }
  anchor.config = need(block::ConfigInfo::extract_config(anchor.mc.root,e.mc.id,block::ConfigInfo::needCapabilities));
  anchor.caller_attests_complete_tip_manifest = anchor.caller_attests_config_from_this_mc_root = true;
  std::vector<block::StdAddress> addresses;
  for (const auto& text : o.asset_wallets) { block::StdAddress a; require(a.parse_addr(text),"invalid asset wallet"); addresses.push_back(a); }
  auto observations = need(assets_analytics::observe_wallets(anchor,addresses,{addresses.size(),o.max_blocks,4*1024*1024}));
  // Match Extractor's native Bits256::to_hex() encoding. AssetFacts deliberately
  // compares provenance byte-for-byte; lowercasing only this copy hid the actual
  // extractor error behind a spurious MC state-root mismatch on the real replay.
  assets_analytics::BatchMeta meta{e.network,anchor.zerostate,"index-pipeline-assets-v1",e.mc.id.to_str(),
      e.mc.state_root.to_hex(),e.mc.gen_utime,lower(e.pin.zerostate.file_hash.to_hex())};
  // One row/address keeps the existing writer envelope cap while preserving the
  // complete tip manifest and every observation; the extractor never samples.
  for (const auto& observation : observations)
    rows.add("asset_wallet_snapshot",observation.wallet.address,"per_metric",
             assets_analytics::render_batch_json(meta,{observation}));
}
} // namespace

Processor::Processor(Options options, std::shared_ptr<Spool> spool)
    : options_(std::move(options)), spool_(std::move(spool)) {
  require(options_.network == "mainnet" || options_.network == "testnet", "unsupported analytics network");
  require(options_.config_history > 0 && options_.config_history <= 4096 && options_.max_pending > 0,
          "invalid analytics history/task limits");
  pin_.zerostate = *core::testing::trusted_mc0(options_.network == "mainnet" ? -239 : -3);
}

void Processor::process(std::uint32_t seqno, const ParsedBlockPtr& p, bool emit) {
  std::string full_id = "mc:" + std::to_string(seqno) + ":identity-unavailable";
  try {
    require(p && p->cell_db_reader_ && !p->mc_block_.shard_blocks_.empty(), "analytics input/reader lease missing");
    const auto& mc = p->mc_block_.shard_blocks_.front();
    require(bool(mc.handle) && mc.handle->id().seqno() == seqno, "analytics seqno mismatch");
    full_id = mc.handle->id().to_str();
    if (emit) spool_->prepare(seqno,full_id);
    auto meta = metadata(mc,pin_);
    const bool older = previous_ && previous_->handle->id().seqno() >= seqno;
    if (!older && meta.status == core::Status::verified_local_archive) {
      auto config = block::ConfigInfo::extract_config(mc.block_state,mc.handle->id(),block::ConfigInfo::needCapabilities);
      if (config.is_ok()) {
        auto cfg = config.move_as_ok(); auto eight = cfg->get_config_param(8);
        if (eight.not_null() && cfg->get_global_version() >= 0)
          configs_[mc.handle->id()] = {mc.handle->id(),meta.mc.state_root,eight->get_hash().as_bits256(),static_cast<uint32_t>(cfg->get_global_version())};
      }
      while (configs_.size() > options_.config_history) configs_.erase(configs_.begin());
    }
    require(p->mc_block_.shard_blocks_.size() <= options_.max_blocks &&
            p->mc_block_.shard_blocks_diff_.size() <= options_.max_blocks && p->blocks_.size() <= options_.max_blocks,
            "analytics block cap exceeded");
    size_t transactions = 0;
    for (const auto& b : p->blocks_) { transactions += b.transactions.size(); require(transactions <= options_.max_transactions,"analytics transaction cap exceeded"); }
    const auto* prior = !older && previous_ && previous_->handle->id() == meta.mc_predecessors.front() ? &*previous_ : nullptr;
    auto verified = core::verify_anchor(p->mc_block_,mc.handle->id(),pin_,{},prior,p->cell_db_reader_);
    bool graph = false; std::string graph_reason = "adjacent full snapshot unavailable (first anchor or prewarm gap)";
    if (prior && previous_evidence_) {
      try { frontier(*verified.evidence,*previous_evidence_,p->mc_block_); graph = true; graph_reason.clear(); }
      catch (const std::exception& e) { graph_reason = e.what(); }
    }
    // Cached committed facts are immutable. Still warm local config/previous
    // context when replaying so an unfinished successor can resume correctly.
    const bool done = emit && spool_->completed(seqno,full_id);
    if (emit && !done) {
      runner::Options ro; ro.network = options_.network; ro.zero_root = lower(pin_.zerostate.root_hash.to_hex());
      ro.zero_file = lower(pin_.zerostate.file_hash.to_hex()); ro.max_blocks = options_.max_blocks;
      ro.max_transactions = options_.max_transactions; ro.max_output_bytes = options_.max_batch_bytes;
      ro.anchor_time_from = 0; ro.anchor_time_to = UINT32_MAX;
      Rows rows(ro,spool_->scope(),meta);
      rows.add("pipeline_provenance",full_id,"observed",
          "{\"entrypoint\":\"IndexScheduler.after_actions\",\"raw_global_id\":" + std::to_string(meta.mc.global_id) +
          ",\"utc_metric_day\":" + std::to_string(meta.mc.gen_utime / 86400 * 86400) +
          ",\"network_pin_source\":\"published immutable network MC0 pair\",\"anchor_id_source\":\"existing scanner local archive full ID\","
          "\"core_verified\":" + (verified.evidence->status == core::Status::verified_local_archive ? "true" : "false") +
          ",\"core_reason\":" + quote(issues(*verified.evidence)) + ",\"frontier_reason\":" + quote(graph_reason) + "}");
      if (verified.evidence->status == core::Status::verified_local_archive) rows.anchor(*verified.evidence,graph);
      else pending(rows,"core_pending",full_id,issues(*verified.evidence));
      auto stage = [&](const std::string& name, auto work) {
        try { work(); }
        catch (const vm::VmError& e) { pending(rows,name + "_pending",full_id,e.get_msg()); }
        catch (const std::exception& e) { pending(rows,name + "_pending",full_id,e.what()); }
      };
      // Validators is independent of shard completeness and lifetime baselines.
      stage("validators",[&] {
        auto validator_error = validators(rows,p->mc_block_,meta,prior);
        if (!validator_error.empty()) pending(rows,"validators_pending",full_id,validator_error);
      });
      stage("flow",[&] {
        require(graph,graph_reason);
        auto ancestry = need(block::ConfigInfo::extract_config(mc.block_state,meta.mc.id,block::ConfigInfo::needPrevBlocks));
        std::map<ton::BlockIdExt,ConfigSource> applied;
        schema::MasterchainBlockDataState supported;
        for (const auto& b : p->mc_block_.shard_blocks_diff_) {
          const auto id = b.handle->id(); auto h = need(block::get_block_header_info(b.block_data->root_cell(),id));
          ton::BlockIdExt ancestral;
          require(h.mc_blkid.seqno() < seqno && ancestry->get_old_mc_block_id(h.mc_blkid.seqno(),ancestral) &&
                  ancestral == h.mc_blkid,"execution config full ID is not in current MC ancestry");
          auto it = configs_.find(h.mc_blkid);
          if (it == configs_.end()) {
            pending(rows,"block_flow_pending",id.to_str(),
                    "historical execution config absent from retained pipeline window: " + h.mc_blkid.to_str());
            continue;
          }
          applied.emplace(id,it->second);
          supported.shard_blocks_diff_.push_back(b);
        }
        require(!supported.shard_blocks_diff_.empty() && supported.shard_blocks_diff_.front().handle->id() == meta.mc.id,
                "raw flow extractor requires historical MC execution config");
        auto flow = ton_analytics::flow::extract(supported,[&](const auto& id) -> std::optional<uint32_t> {
          auto it = applied.find(native_id(id)); return it == applied.end() ? std::nullopt : std::make_optional(it->second.version);
        },{options_.max_blocks,options_.max_transactions,options_.max_transactions,500000,options_.max_transactions});
        rows.flow(flow,applied);
        rows.add("flow_coverage",full_id,"per_block",
            "{\"extracted_blocks\":" + std::to_string(flow.blocks.size()) +
            ",\"first_included_blocks\":" + std::to_string(p->mc_block_.shard_blocks_diff_.size()) +
            ",\"calendar_day_complete\":false}");
      });
      stage("wallets",[&] {
        auto events = w::events::extract(*p); wallet_events(rows,events);
        stage("wallet_stage",[&] { require(graph,graph_reason); wallet_stage(rows,*p,*verified.evidence,events,options_); });
        rows.add("wallet_coverage",full_id,"incomplete",
            "{\"daily_activations\":null,\"dau\":null,\"mau\":null,\"pending_post_codes\":" + std::to_string(events.pending_post_codes) +
            ",\"pending_execution_codes\":" + std::to_string(events.pending_execution_codes) +
            ",\"reason\":\"no lifetime baseline or closed UTC-day frontier\"}");
      });
      stage("nft",[&] {
        namespace n = assets_analytics::nft_events;
        require(!p->blocks_.empty(),"missing parsed MC");
        const auto& b = p->blocks_.front();
        require(parsed_id(b) == meta.mc.id,"parsed MC full ID mismatch");
        auto batch = n::extract(*p,{b.workchain,b.shard,b.seqno,b.root_hash,b.file_hash},
            {options_.max_blocks,options_.max_transactions,options_.max_transactions,options_.max_batch_bytes});
        require(batch.ok(),batch.error);
        for (const auto& c : batch.candidates) {
          auto opt_hash = [](const auto& h) { return h ? quote(lower(*h)) : "null"; };
          rows.add("nft_initialization_candidate",c.transaction_hash,"unresolved",
              "{\"source_block\":" + id_json(parsed_id(c.source_block)) + ",\"account\":" + quote(c.account) +
              ",\"tx_hash\":" + quote(lower(c.transaction_hash)) + ",\"lt\":" + quote(std::to_string(c.lt)) +
              ",\"now\":" + std::to_string(c.now) + ",\"utc_day_start\":" + std::to_string(c.now / 86400 * 86400) +
              ",\"state_hash_before\":" + quote(lower(c.state_hash_before)) + ",\"state_hash_after\":" + quote(lower(c.state_hash_after)) +
              ",\"supplied_state_init_hash\":" + opt_hash(c.supplied_state_init_hash) +
              ",\"accepted_state_init_hash\":" + opt_hash(c.accepted_state_init_hash) +
              ",\"accepted_boc_sha256\":" + (c.accepted_state_init_boc ? quote(digest(*c.accepted_state_init_boc)) : "null") +
              ",\"accepted_boc_bytes\":" + std::to_string(c.accepted_state_init_boc ? c.accepted_state_init_boc->size() : 0) +
              ",\"minted\":null,\"reason\":" + quote(c.reason) + "}");
        }
        rows.add("nft_coverage",full_id,"incomplete",
            "{\"all_candidates_serialized\":true,\"examined_transactions\":" + std::to_string(batch.examined_transactions) +
            ",\"candidates\":" + std::to_string(batch.candidates.size()) +
            ",\"minted\":null,\"reason\":\"historical collection binding and lifetime coverage not established\"}");
      });
      stage("assets",[&] { asset_snapshot(rows,*p,*verified.evidence,options_); });
      rows.add("supply_coverage",full_id,"not_requested",
          "{\"total_nanoton\":null,\"reason\":\"full native supply scan is not a per-block processor; use explicit anchor calculation\"}");
      spool_->commit(seqno,full_id,rows.text());
    }
    if (!older) {
      previous_ = mc; previous_reader_ = p->cell_db_reader_; previous_evidence_ = verified.evidence;
    }
  } catch (const vm::VmError& e) {
    if (emit) spool_->failed(seqno,full_id,e.get_msg());
    throw std::runtime_error(e.get_msg());
  } catch (const std::exception& e) {
    if (emit) spool_->failed(seqno,full_id,e.what());
    throw;
  }
}

void ProcessorActor::begin(std::uint32_t first) { CHECK(!next_ && pending_.empty()); next_ = first; }
void ProcessorActor::execute(std::uint32_t seqno, Pending p) {
  try { processor_.process(seqno,p.parsed,p.emit); p.promise.set_value(td::Unit{}); }
  catch (const std::exception& e) { p.promise.set_error(td::Status::Error(td::Slice(e.what()))); }
}
void ProcessorActor::process(std::uint32_t seqno, ParsedBlockPtr p, bool emit, td::Promise<td::Unit> promise) {
  if (!next_) { promise.set_error(td::Status::Error("analytics not initialized")); return; }
  if (seqno < next_) { execute(seqno,{std::move(p),emit,std::move(promise)}); return; }
  if (pending_.size() >= limit_ || pending_.count(seqno)) {
    promise.set_error(td::Status::Error("analytics input queue cap/duplicate")); return;
  }
  pending_.emplace(seqno,Pending{std::move(p),emit,std::move(promise)});
  while (pending_.count(next_)) {
    auto it = pending_.find(next_); auto item = std::move(it->second); pending_.erase(it);
    execute(next_++,std::move(item));
  }
}
} // namespace tonstat::pipeline
