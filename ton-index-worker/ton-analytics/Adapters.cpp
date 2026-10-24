#include "Adapters.h"
#include "../ton-analytics-validators/ValidatorCoreBridge.h"
#include "../ton-analytics-validators/ValidatorFacts.h"
#include "../ton-analytics-wallets/WalletEventExtractor.h"
#include "../ton-analytics-accounts/Native.h"
#include "../tondb-scanner/src/assets_analytics/NftEvents.h"
#include "crypto/block/mc-config.h"
#include "td/utils/base64.h"
#include <algorithm>
#include <utility>

namespace tonstat::runner {
namespace {
bool checked(const core::AnchorEvidence& e, const std::string& code, const std::string& observed) {
  return std::any_of(e.checks.begin(), e.checks.end(), [&](const core::Check& c) {
    return c.code == code && c.subject == e.mc.id.to_str() && c.observed == observed;
  });
}
bool anchored(const analytics::validators::stage::Input& in) {
  namespace v = analytics::validators::stage;
  if (!in.expected_mc_id.is_masterchain() || !in.expected_mc_id.is_valid_full() ||
      in.expected_mc_id.id.shard != ton::shardIdAll || in.expected_post_state_root == td::Bits256{}) return false;
  for (const auto* c : {&in.anchor.raw_block_file_hash, &in.anchor.header_and_predecessor, &in.anchor.state_update})
    if (c->status != v::Status::ready || !c->reason.empty() || c->mc_id != in.expected_mc_id ||
        c->post_state_root != in.expected_post_state_root) return false;
  return true;
}
template <class Id> ton::BlockIdExt base64_id(const Id& b) {
  auto decode = [](const std::string& s) {
    auto x = td::base64_decode(s); require(x.is_ok(), "invalid parsed block hash base64");
    auto bytes = x.move_as_ok(); require(bytes.size() == 32, "parsed block hash is not 256 bits");
    td::Bits256 v; v.as_slice().copy_from(bytes); return v;
  };
  return {b.workchain, static_cast<uint64_t>(b.shard), b.seqno, decode(b.root_hash), decode(b.file_hash)};
}
std::string code_json(const ton_analytics::wallets::events::CodeFact& c) {
  using C = ton_analytics::wallets::events::Classification;
  const char* classification = c.classification == C::included_wallet ? "included_wallet" :
      c.classification == C::excluded_code ? "excluded_code" : c.classification == C::outside_registry ? "outside_registry" : "pending";
  return "{\"classification\":" + quote(classification) + ",\"resolution\":" + std::to_string(static_cast<int>(c.resolution)) +
      ",\"source\":" + quote(c.source) + ",\"code_hash\":" + (c.code_hash_hex ? quote(lower(*c.code_hash_hex)) : "null") +
      ",\"wallet_type\":" + (c.wallet_type_id ? quote(*c.wallet_type_id) : "null") + "}";
}
std::string tx_json(const ton_analytics::wallets::events::TxId& t) {
  return "\"account\":" + quote(t.account) + ",\"lt\":" + quote(std::to_string(t.lt)) +
      ",\"tx_hash\":" + quote(lower(t.hash_hex)) + ",\"now\":" + std::to_string(t.now) +
      ",\"utc_day_start\":" + std::to_string(t.utc_day_start) + ",\"source_block\":" + id_json(base64_id(t.shard));
}
} // namespace
analytics::validators::stage::Input validator_input(const analytics::validators::stage::Output& out) {
  namespace v = analytics::validators::stage;
  v::Input in;
  in.network_zerostate = out.network_zerostate;
  in.network_zerostate_file_hash = out.network_zerostate_file_hash;
  in.expected_mc_id = out.mc_id; in.expected_post_state_root = out.post_state_root;
  in.anchor = out.anchor;
  // This is the domain decoder's own reviewed hash, not a caller-extensible list.
  in.supported_elector_code_hashes.push_back(bits(std::string(analytics::validators::kReviewedElectorCodeHash)));
  return in;
}
std::optional<analytics::validators::stage::ElectionBoundary> validator_boundary(
    const core::AnchorEvidence& e, const analytics::validators::stage::Input& current,
    const analytics::validators::stage::Input& previous,
    const std::optional<td::Bits256>& previous_config36,
    const analytics::validators::election::Observation& now,
    const analytics::validators::election::Observation& prior) {
  namespace v = analytics::validators::stage;
  namespace election = analytics::validators::election;
  const auto matches = [](const election::Observation& o, const v::Input& in) {
    return o.state_update_verified && o.mc_id == in.expected_mc_id &&
        o.state_hash == in.expected_post_state_root && o.network_zerostate == in.network_zerostate;
  };
  if (!anchored(current) || !anchored(previous) ||
      e.status != core::Status::verified_local_archive || !e.snapshot_integrity_checked || !e.issues.empty() ||
      e.scope != core::Scope::full_snapshot || e.continuity_status != core::Status::verified_local_archive ||
      !e.continuity_reason.empty() || e.mc.id != current.expected_mc_id ||
      e.mc.state_root != current.expected_post_state_root || e.mc.state_update_new != e.mc.state_root ||
      e.mc.state_update_old != previous.expected_post_state_root ||
      e.previous_mc != previous.expected_mc_id || e.previous_mc_state_root != previous.expected_post_state_root ||
      e.mc_predecessors.size() != 1 || e.mc_predecessors.front() != previous.expected_mc_id ||
      previous.expected_mc_id.seqno() >= current.expected_mc_id.seqno() ||
      previous.expected_mc_id.seqno() + 1 != current.expected_mc_id.seqno() ||
      previous.expected_post_state_root == current.expected_post_state_root ||
      previous.network_zerostate != current.network_zerostate ||
      previous.network_zerostate_file_hash != current.network_zerostate_file_hash ||
      lower(e.pin.zerostate.root_hash.to_hex()) != lower(current.network_zerostate) ||
      lower(e.pin.zerostate.file_hash.to_hex()) != lower(current.network_zerostate_file_hash) ||
      !checked(e, "adjacent_mc_predecessor_full_id_and_state_update_old",
               previous.expected_mc_id.to_str() + " / " + previous.expected_post_state_root.to_hex()) ||
      !matches(now, current) || !matches(prior, previous) ||
      !now.config36_hash || *now.config36_hash == td::Bits256{} || previous_config36 == now.config36_hash ||
      !now.requested_election_id || *now.requested_election_id == 0 ||
      now.requested_vset_hash != now.config36_hash || prior.requested_vset_hash != now.config36_hash ||
      prior.requested_election_id != now.requested_election_id ||
      now.past.status != election::Status::ready || !now.past_present.value_or(false) ||
      prior.past.status != election::Status::ready || !prior.past_present || *prior.past_present)
    return std::nullopt;
  v::ElectionBoundary b;
  b.first_post_election = {v::Status::ready, "", current.expected_mc_id, current.expected_post_state_root};
  b.previous_mc_id = previous.expected_mc_id; b.previous_post_state_root = previous.expected_post_state_root;
  b.previous_state_and_config36 = {v::Status::ready, "", b.previous_mc_id, b.previous_post_state_root};
  b.previous_config36_hash = previous_config36;
  b.election_id = *now.requested_election_id; b.selected_vset_hash = *now.config36_hash;
  return b;
}
std::string validators(Rows& rows, const schema::MasterchainBlockDataState& data,
                const core::AnchorEvidence& e, const schema::BlockDataState* previous) {
  namespace v = analytics::validators::stage;
  // Use the domain's native bridge, not ready booleans fabricated from check
  // names. This rechecks the original MC BoC, full ID, state, network and pin;
  // #34 remains independent of shard-range/snapshot completeness.
  auto verified = tonstat::validators::run_verified_mc(data, e.mc.id, e.pin,
      {bits(std::string(analytics::validators::kReviewedElectorCodeHash))});
  auto out = std::move(verified.stage);
  auto in = validator_input(out);
  if (anchored(in) && previous && previous->handle && e.previous_mc && e.previous_mc_state_root &&
      *e.previous_mc == previous->handle->id() &&
      e.continuity_status == core::Status::verified_local_archive &&
      checked(e, "adjacent_mc_predecessor_full_id_and_state_update_old",
              e.previous_mc->to_str() + " / " + e.previous_mc_state_root->to_hex())) {
    schema::MasterchainBlockDataState prior_data;
    prior_data.shard_blocks_.push_back(*previous);
    const auto prior_verified = tonstat::validators::run_verified_mc(prior_data, *e.previous_mc, e.pin,
        in.supported_elector_code_hashes);
    const auto prior_in = validator_input(prior_verified.stage);
    if (!anchored(prior_in)) return write_validators(rows, out);
    auto cfg = block::ConfigInfo::extract_config(previous->block_state, previous->handle->id(), 0);
    if (cfg.is_error()) return write_validators(rows, out);
    auto prior36 = cfg.move_as_ok()->get_config_param(36);
    analytics::validators::election::Input oi;
    oi.network_zerostate = in.network_zerostate; oi.expected_mc_id = in.expected_mc_id;
    oi.expected_state_hash = in.expected_post_state_root; oi.state_update_verified = true;
    oi.supported_elector_code_hashes = in.supported_elector_code_hashes;
    auto observation = analytics::validators::election::observe_election(data, oi);
    if (observation.is_ok()) {
      auto o = observation.move_as_ok();
      if (o.config36_hash && o.requested_election_id && o.past.status == analytics::validators::election::Status::ready &&
          o.past_present.value_or(false) && (prior36.is_null() || prior36->get_hash().as_bits256() != *o.config36_hash)) {
        // A new #36 alone does not prove the frozen principal is original:
        // also require the exact election absent in the immediately prior state.
        auto prior_input = oi;
        prior_input.expected_mc_id = prior_in.expected_mc_id;
        prior_input.expected_state_hash = prior_in.expected_post_state_root;
        prior_input.election_id = *o.requested_election_id;
        prior_input.expected_vset_hash = *o.config36_hash;
        auto prior_result = analytics::validators::election::observe_election(prior_data, prior_input);
        if (prior_result.is_ok()) {
          const auto prior = prior_result.move_as_ok();
          const auto prior_hash = prior36.not_null() ? std::make_optional(prior36->get_hash().as_bits256()) : std::nullopt;
          in.election_boundary = validator_boundary(e, in, prior_in, prior_hash, o, prior);
          if (in.election_boundary) out = v::run(data, in);
        }
      }
    }
  }
  return write_validators(rows, out);
}
std::string write_validators(Rows& rows, const analytics::validators::stage::Output& out) {
  namespace v = analytics::validators::stage;
  rows.add("validators", out.mc_id.to_str(), "per_metric", tonstat::validators::render_batch_json(out));
  for (const auto* m : {&out.count, &out.frozen_remaining, &out.accepted, &out.selected_initial})
    if (m->status == v::Status::invalid) return "invalid Validators extraction: " + m->reason;
  if (out.count.status != v::Status::ready) return "Validators config34 extraction failed: " + out.count.reason;
  return {};
}
void accounts_sample(Rows& rows, const core::MaterializedAnchor& view, const Options& o) {
  if (!o.accounts_limit) return;
#if defined(TON_ANALYTICS_WITH_ACCOUNTS) && TON_ANALYTICS_WITH_ACCOUNTS == 1
  accounts::Caps caps; caps.max_blocks = o.max_blocks; caps.max_transactions = o.max_transactions;
  auto s = accounts::scan_snapshot(view.snapshot(), o.network, o.zero_root, o.accounts_limit, false, caps);
  rows.add("accounts_sample", view.evidence().mc.id.to_str(), "incomplete",
      "{\"sample_only\":true,\"network_total\":null,\"visited\":" + std::to_string(s.visited) +
      ",\"lower_bound_uninit\":" + std::to_string(s.counts.uninit) + ",\"lower_bound_active\":" + std::to_string(s.counts.active) +
      ",\"lower_bound_frozen\":" + std::to_string(s.counts.frozen) + ",\"reason\":" + quote(s.reason) + "}");
#else
  (void)rows; (void)view;
  throw std::runtime_error("Accounts sample adapter not built; see TON_ANALYTICS_WITH_ACCOUNTS compatibility notes");
#endif
}
void parsed_events(Rows& rows, const ParsedBlock& parsed, const ton_analytics::flow::Batch& flow, const Options& o) {
  require(parsed.blocks_.size() == flow.blocks.size(), "parsed/raw block inventory mismatch");
  std::map<ton::BlockIdExt, uint64_t> counts;
  for (const auto& f : flow.blocks) counts.emplace(native_id(f.id), f.tx_count);
  size_t total = 0;
  for (const auto& b : parsed.blocks_) {
    auto id = base64_id(b); auto it = counts.find(id);
    require(it != counts.end() && it->second == b.transactions.size(), "parsed/raw transaction inventory mismatch");
    total += b.transactions.size(); counts.erase(it);
  }
  require(total <= o.max_transactions && counts.empty(), "parser inventory/budget failed");
  if (o.wallet_events) {
    auto batch = ton_analytics::wallets::events::extract(parsed);
    for (const auto& w : batch.active_witnesses)
      rows.add("wallet_active_witness", w.tx.hash_hex, "observed_not_lifetime_first",
          "{" + tx_json(w.tx) + ",\"registry_sha256\":" + quote(batch.registry_sha256) +
          ",\"orig_status\":" + std::to_string(static_cast<int>(w.orig_status)) + ",\"end_status\":" + std::to_string(static_cast<int>(w.end_status)) +
          ",\"post_state_hash\":" + quote(lower(w.post_state_hash_hex)) + ",\"activation_candidate\":" + (w.activation_candidate ? "true" : "false") +
          ",\"post_code\":" + code_json(w.post_code) + "}");
    for (const auto& w : batch.sends)
      rows.add("wallet_qualifying_send", w.tx.hash_hex, "per_code_resolution",
          "{" + tx_json(w.tx) + ",\"registry_sha256\":" + quote(batch.registry_sha256) +
          ",\"message_hash\":" + quote(lower(w.message_hash_hex)) + ",\"execution_code\":" + code_json(w.execution_code) + "}");
    rows.add("wallet_coverage", native_id(flow.mc_id).to_str(), "incomplete",
        "{\"all_facts_serialized\":true,\"active_witnesses\":" + std::to_string(batch.active_witnesses.size()) +
        ",\"qualifying_sends\":" + std::to_string(batch.sends.size()) + ",\"pending_post_codes\":" + std::to_string(batch.pending_post_codes) +
        ",\"pending_execution_codes\":" + std::to_string(batch.pending_execution_codes) +
        ",\"daily_activations\":null,\"dau\":null,\"mau\":null,\"reason\":\"no lifetime baseline or closed UTC-day frontier\"}");
  }
  if (o.nft_candidates) {
    namespace n = assets_analytics::nft_events;
    const auto& mc = parsed.blocks_.front();
    auto batch = n::extract(parsed, {mc.workchain, mc.shard, mc.seqno, mc.root_hash, mc.file_hash},
                            {o.max_blocks, o.max_transactions, o.max_transactions, static_cast<size_t>(o.max_output_bytes)});
    require(batch.ok(), "NFT candidate extraction failed: " + batch.error);
    for (const auto& c : batch.candidates)
      rows.add("nft_initialization_candidate", c.transaction_hash, "unresolved",
          "{\"source_block\":" + id_json(base64_id(c.source_block)) + ",\"account\":" + quote(c.account) +
          ",\"tx_hash\":" + quote(lower(c.transaction_hash)) + ",\"lt\":" + quote(std::to_string(c.lt)) + ",\"now\":" + std::to_string(c.now) +
          ",\"state_hash_before\":" + quote(lower(c.state_hash_before)) + ",\"state_hash_after\":" + quote(lower(c.state_hash_after)) +
          ",\"minted\":null,\"reason\":" + quote(c.reason) + "}");
    rows.add("nft_coverage", native_id(flow.mc_id).to_str(), "incomplete",
        "{\"all_candidates_serialized\":true,\"examined_transactions\":" + std::to_string(batch.examined_transactions) +
        ",\"candidates\":" + std::to_string(batch.candidates.size()) +
        ",\"minted\":null,\"reason\":\"historical getters, collection binding and lifetime coverage not established\"}");
  }
}
} // namespace tonstat::runner
