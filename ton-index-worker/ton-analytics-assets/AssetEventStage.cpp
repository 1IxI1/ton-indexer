#include "AssetEventStage.h"

#include "../ton-analytics-core/AnchorEvidence.h"
#include "td/utils/base64.h"
#include "td/utils/crypto.h"
#include "common/checksum.h"

#include <algorithm>
#include <limits>
#include <stdexcept>

namespace assets_analytics::event_stage {
namespace {

Id from_native(const ton::BlockIdExt& b) {
  return {b.id.workchain, static_cast<int64_t>(b.id.shard), b.id.seqno,
          td::base64_encode(b.root_hash.as_slice()), td::base64_encode(b.file_hash.as_slice())};
}

bool same_set(const std::vector<Id>& a, const std::vector<Id>& b) {
  if (a.size() != b.size()) return false;
  for (const auto& id : a) {
    if (std::count_if(b.begin(), b.end(), [&](const Id& x) { return same(id, x); }) != 1)
      return false;
  }
  return true;
}

bool bound_input(const Request& r) {
  if ((r.enable_nft && (r.nft_budget.max_blocks > 4096 || r.nft_budget.max_transactions > 10000 ||
      r.nft_budget.max_candidates > 10000 || r.nft_budget.max_evidence_bytes > kMaxBatchBytes ||
      r.first_included.size() > r.nft_budget.max_blocks)) ||
      (r.enable_dns && (r.dns_limits.max_blocks > 4096 || r.dns_limits.max_transactions > 10000 ||
      r.dns_limits.max_candidates > 10000 || r.dns_limits.max_provenance_bytes > kMaxBatchBytes ||
      r.dns_limits.max_addresses > 4096 || r.dns_limits.max_total_messages > 50000 ||
      r.dns_limits.max_messages_per_tx > 256 ||
      r.first_included.size() > r.dns_limits.max_blocks ||
      r.reviewed_dns_items.size() > r.dns_limits.max_addresses))) return false;
  size_t bytes = 0;
  const auto add = [&](size_t n) {
    if (n > kMaxBatchBytes - bytes) return false;
    bytes += n;
    return true;
  };
  if (!add(r.network.size()) || !add(r.zerostate_root_hash.size()) ||
      !add(r.zerostate_file_hash.size()) || !add(r.calc_version.size()) ||
      !add(r.registry_digest.size())) return false;
  for (const auto& id : r.first_included)
    if (!add(sizeof(Id) + id.root_hash.size() + id.file_hash.size())) return false;
  for (const auto& id : r.current_tips)
    if (!add(sizeof(Id) + id.root_hash.size() + id.file_hash.size())) return false;
  for (const auto& a : r.reviewed_nft_items) if (!add(a.size())) return false;
  for (const auto& a : r.reviewed_dns_items) if (!add(a.size())) return false;
  return true;
}

} // namespace

Batch extract(const ParsedBlock& parsed, const tonstat::core::AnchorEvidence& e, const Request& r) {
  if (!valid_request(r) || !bound_input(r)) return fail(r, "invalid request or input budget exceeded");
  if (e.status != tonstat::core::Status::verified_local_archive ||
      e.scope != tonstat::core::Scope::full_snapshot || !e.snapshot_integrity_checked ||
      !e.diff_handle_inclusion_checked || !e.issues.empty() ||
      e.network != r.network || !same(from_native(e.pin.zerostate),
                                      { -1, std::numeric_limits<int64_t>::min(), 0,
                                        r.zerostate_root_hash, r.zerostate_file_hash }) ||
      !same(from_native(e.mc.id), r.mc))
    return fail(r, "anchor/network/MC0 full ID or local snapshot proof mismatch");
  std::vector<Id> included, expected_tips, loaded_tips;
  for (const auto& b : e.first_included) included.push_back(from_native(b.id));
  for (const auto& b : e.expected_shard_tips) expected_tips.push_back(from_native(b));
  for (const auto& b : e.shard_tips) loaded_tips.push_back(from_native(b.id));
  if (included.size() != r.first_included.size() ||
      !std::equal(included.begin(), included.end(), r.first_included.begin(), same) ||
      !same_set(expected_tips, r.current_tips) || !same_set(loaded_tips, r.current_tips) ||
      parsed.blocks_.size() != r.first_included.size() ||
      parsed.mc_block_.shard_blocks_diff_.size() != r.first_included.size())
    return fail(r, "first-included diff or current tip manifest differs from anchor");
  for (size_t i = 0; i < parsed.blocks_.size(); ++i) {
    const auto& b = parsed.blocks_[i];
    const auto& raw = parsed.mc_block_.shard_blocks_diff_[i];
    if (!raw.handle || raw.block_data.is_null() ||
        !same(from_native(raw.handle->id()), r.first_included[i]) ||
        !same(from_native(raw.block_data->block_id()), r.first_included[i]))
      return fail(r, "parser original diff handle/BoC full ID differs from verified anchor");
    if (!same({b.workchain, b.shard, b.seqno, b.root_hash, b.file_hash}, r.first_included[i]) ||
        b.gen_utime < 0 || static_cast<uint32_t>(b.gen_utime) != e.first_included[i].gen_utime)
      return fail(r, "parser block full ID/time differs from anchor diff");
  }

  std::optional<nft_events::Result> nft;
  std::optional<dns::Batch> dns_batch;
  if (r.enable_nft) {
    const nft_events::BlockId mc_nft{r.mc.workchain, r.mc.shard, r.mc.seqno,
                                      r.mc.root_hash, r.mc.file_hash};
    nft = nft_events::extract(parsed, mc_nft, r.nft_budget);
    if (!nft->ok()) return fail(r, "NFT extractor: " + nft->error);
  }
  if (r.enable_dns) {
    dns::Request dns_request;
    dns_request.network = r.network;
    dns_request.zerostate = r.zerostate_root_hash;
    dns_request.mc_block = {r.mc.workchain, r.mc.shard, r.mc.seqno, r.mc.root_hash, r.mc.file_hash};
    dns_request.registry_digest = r.registry_digest;
    dns_request.item_addresses = r.reviewed_dns_items;
    dns_request.limits = r.dns_limits;
    dns_batch = dns::extract_dns_auction_candidates(parsed, dns_request);
    if (!dns_batch->valid) return fail(r, "DNS extractor: " + dns_batch->reason);
  }

  std::vector<Fact> n, d;
  if (nft) n.reserve(nft->candidates.size());
  if (dns_batch) d.reserve(dns_batch->candidates.size());
  if (nft) for (const auto& c : nft->candidates) {
    Fact f;
    f.family = "nft"; f.signal = "possible_first_initialization";
    f.item = c.account; f.tx_hash = c.transaction_hash; f.lt = c.lt; f.now = c.now;
    f.mc = from(c.mc_anchor); f.source = from(c.source_block);
    f.state_before = c.state_hash_before; f.state_after = c.state_hash_after;
    f.status_before = account_status(c.orig_status); f.status_after = account_status(c.end_status);
    f.reason = c.reason; f.reviewed_item = std::find(r.reviewed_nft_items.begin(),
         r.reviewed_nft_items.end(), c.account) != r.reviewed_nft_items.end();
    if (c.supplied_state_init_hash) f.supplied_init_hash = *c.supplied_state_init_hash;
    if (c.accepted_state_init_hash) f.accepted_init_hash = *c.accepted_state_init_hash;
    if (c.accepted_state_init_boc) {
      f.accepted_boc_bytes = c.accepted_state_init_boc->size();
      f.accepted_boc_sha256 = td::sha256_bits256(td::Slice(*c.accepted_state_init_boc)).to_hex();
    }
    n.push_back(std::move(f));
  }
  using Key = std::tuple<std::string, std::string, std::string>;
  std::map<Key, size_t> occurrences;
  if (dns_batch) for (const auto& c : dns_batch->candidates) {
    if (c.network != r.network || c.zerostate != r.zerostate_root_hash ||
        c.registry_digest != r.registry_digest) return fail(r, "DNS candidate registry/network mismatch");
    Fact f;
    f.family = "dns"; f.signal = signal_name(c.signal);
    f.signal_ordinal = occurrences[Key{c.tx.hash, c.tx.item_address, f.signal}]++;
    auto trigger = dns_trigger(c, f.signal_ordinal);
    if (!trigger) return fail(r, "DNS candidate lacks distinct triggering message");
    f.trigger_message_hash = *trigger;
    f.item = c.tx.item_address; f.tx_hash = c.tx.hash; f.lt = c.tx.lt; f.now = c.tx.now;
    f.mc = from(c.mc_block); f.source = from(c.tx.block);
    f.state_before = c.tx.state_hash_before; f.state_after = c.tx.state_hash_after;
    f.reason = c.reason; f.reviewed_item = true; f.aborted = c.tx.aborted;
    if (c.tx.incoming) f.messages.push_back(*c.tx.incoming);
    f.messages.insert(f.messages.end(), c.tx.outgoing.begin(), c.tx.outgoing.end());
    d.push_back(std::move(f));
  }
  Batch out = reduce(r, nft, dns_batch, std::move(n), std::move(d));
  if (out.valid) {
    out.snapshot_integrity_checked = true;
    out.diff_exhaustiveness_checked = e.diff_exhaustiveness_checked;
  }
  return out;
}

} // namespace assets_analytics::event_stage
