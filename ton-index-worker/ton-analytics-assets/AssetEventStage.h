#pragma once

#include "../tondb-scanner/src/assets_analytics/NftEvents.h"
#include "../tondb-scanner/src/assets_analytics/DnsAuctionEvents.h"

#include <algorithm>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <tuple>
#include <vector>

struct ParsedBlock;
namespace tonstat::core { struct AnchorEvidence; }

namespace assets_analytics::event_stage {

constexpr size_t kMaxBatchBytes = 256 * 1024;

struct Id {
  int32_t workchain{};
  int64_t shard{};
  uint32_t seqno{};
  std::string root_hash, file_hash; // parser base64 hashes, not coordinates alone
};

inline bool same(const Id& a, const Id& b) {
  return std::tie(a.workchain, a.shard, a.seqno, a.root_hash, a.file_hash) ==
         std::tie(b.workchain, b.shard, b.seqno, b.root_hash, b.file_hash);
}
// The native adapters canonicalize StdAddress::addr.to_hex() (which can be
// uppercase). Reject noncanonical producer/registry spellings rather than
// silently treating a reviewed NFT as an unrelated, unreviewed candidate.
inline bool canonical_raw_address(const std::string& address) {
  const auto pos = address.find(':');
  if (pos == std::string::npos || pos == 0 || address.size() - pos != 65) return false;
  int32_t workchain = 0;
  const auto parsed = std::from_chars(address.data(), address.data() + pos, workchain);
  if (parsed.ec != std::errc{} || parsed.ptr != address.data() + pos ||
      std::to_string(workchain) != address.substr(0, pos)) return false;
  return nft_events::canonical_account_address(workchain, address.substr(pos + 1)) == address &&
         dns::canonical_account_address(workchain, address.substr(pos + 1)) == address;
}
inline Id from(const nft_events::BlockId& b) {
  return {b.workchain, b.shard, b.seqno, b.root_hash, b.file_hash};
}
inline Id from(const dns::BlockId& b) {
  return {b.workchain, b.shard, b.seqno, b.root_hash, b.file_hash};
}

inline const char* signal_name(dns::Signal signal) {
  switch (signal) {
    case dns::Signal::first_auction_candidate: return "first_auction_candidate";
    case dns::Signal::bid_candidate: return "bid_candidate";
    case dns::Signal::refund_candidate: return "refund_candidate";
    case dns::Signal::expiry_candidate: return "expiry_candidate";
    case dns::Signal::settlement_candidate: return "settlement_candidate";
    case dns::Signal::release_reauction_candidate: return "release_reauction_candidate";
    case dns::Signal::secondary_transfer_candidate: return "secondary_transfer_candidate";
    case dns::Signal::other_item_transaction: return "other_item_transaction";
  }
  return "invalid_signal";
}
inline const char* account_status(nft_events::Status status) {
  switch (status) {
    case nft_events::Status::nonexist: return "nonexist";
    case nft_events::Status::uninit: return "uninit";
    case nft_events::Status::frozen: return "frozen";
    case nft_events::Status::active: return "active";
  }
  return "invalid";
}

// A nullopt is invalid (e.g. a second refund signal with only one refund
// message). Empty string is valid only for a single time/state-only signal.
inline std::optional<std::string> dns_trigger(const dns::Candidate& c, size_t ordinal) {
  if (c.signal == dns::Signal::refund_candidate || c.signal == dns::Signal::settlement_candidate) {
    const auto opcode = c.signal == dns::Signal::refund_candidate ? 0x557cea20U : 0x370fec51U;
    size_t hit = 0;
    for (const auto& msg : c.tx.outgoing)
      if (msg.opcode == opcode && hit++ == ordinal) return msg.hash;
    return std::nullopt;
  }
  if (ordinal) return std::nullopt;
  if (c.signal == dns::Signal::expiry_candidate || c.signal == dns::Signal::other_item_transaction)
    return std::string{};
  if (!c.tx.incoming) return std::nullopt;
  return c.tx.incoming->hash;
}

struct Request {
  std::string network, zerostate_root_hash, zerostate_file_hash;
  Id mc;
  // Exact ordered parser diff, not the repeating current tip set. The tip list
  // is a separate MC snapshot manifest; neither list proves day coverage.
  std::vector<Id> first_included, current_tips;
  std::string calc_version, registry_digest;
  bool enable_nft{}, enable_dns{}; // explicitly selected independent event scopes
  std::vector<std::string> reviewed_nft_items, reviewed_dns_items;
  nft_events::Budget nft_budget{};
  dns::Limits dns_limits{};
  size_t max_json_bytes{kMaxBatchBytes};
};

struct Fact {
  std::string family, signal, item, tx_hash, reason;
  Id mc, source;
  uint64_t lt{};
  uint32_t now{};
  // Zero-based occurrence of this signal on this item transaction. Repeated
  // outgoing refund/settlement messages have distinct ordinals and trigger hashes.
  size_t signal_ordinal{};
  std::string trigger_message_hash;
  std::string state_before, state_after;
  std::string status_before, status_after;
  bool reviewed_item{};
  // NFT: supplied/accepted StateInit hash, BoC SHA256 and byte count, never BoC.
  std::string supplied_init_hash, accepted_init_hash, accepted_boc_sha256;
  size_t accepted_boc_bytes{};
  // DNS: each signal retains the WHOLE tx message list, even when several
  // signals refer to the same tx. These are raw candidate evidence, not price.
  std::vector<dns::Message> messages;
  bool aborted{};
};

struct Metric {
  std::string name, reason;
  std::string status{"unresolved"}; // or not_requested; value is ALWAYS null
  bool ready{false};
  // No numeric field by design: candidate evidence cannot establish a mint,
  // first DNS sale, winning bid, or lifetime/day coverage.
};

struct Batch {
  bool valid{false};
  std::string failure;
  Request provenance;
  std::vector<Fact> facts; // complete owned set, never sampled/truncated
  size_t nft_fact_count{}, dns_fact_count{}, nft_examined_transactions{};
  bool snapshot_integrity_checked{}, diff_exhaustiveness_checked{};
  Metric nft{"nft_minted", "unresolved: historical initialization, collection binding and lifetime missing"};
  Metric dns_sold{"dns_first_sale", "unresolved: primary auction pre/post settlement and lifetime missing"};
  Metric dns_volume{"dns_trading_volume", "unresolved: first sale and winning bid missing"};
};

inline bool valid_request(const Request& r) {
  if (r.network.empty() || r.zerostate_root_hash.empty() || r.zerostate_file_hash.empty() ||
      r.calc_version.empty() || r.registry_digest.size() != 64 || !r.mc.seqno ||
      r.mc.workchain != -1 || r.mc.root_hash.empty() || r.mc.file_hash.empty() ||
      r.first_included.empty() || !same(r.first_included.front(), r.mc) ||
      r.current_tips.empty() || (!r.enable_nft && !r.enable_dns) ||
      !r.max_json_bytes || r.max_json_bytes > kMaxBatchBytes ||
      (r.enable_nft && (r.reviewed_nft_items.empty() || !r.nft_budget.max_blocks ||
                        !r.nft_budget.max_transactions || !r.nft_budget.max_candidates ||
                        !r.nft_budget.max_evidence_bytes)) ||
      (r.enable_dns && (r.reviewed_dns_items.empty() || !r.dns_limits.max_blocks ||
                        !r.dns_limits.max_addresses || !r.dns_limits.max_transactions ||
                        !r.dns_limits.max_messages_per_tx || !r.dns_limits.max_total_messages ||
                        !r.dns_limits.max_candidates || !r.dns_limits.max_provenance_bytes)) ||
      (!r.enable_nft && (!r.reviewed_nft_items.empty() || r.nft_budget.max_blocks ||
                         r.nft_budget.max_transactions || r.nft_budget.max_candidates ||
                         r.nft_budget.max_evidence_bytes)) ||
      (!r.enable_dns && (!r.reviewed_dns_items.empty() || r.dns_limits.max_addresses ||
                         r.dns_limits.max_blocks || r.dns_limits.max_transactions ||
                         r.dns_limits.max_messages_per_tx || r.dns_limits.max_total_messages ||
                         r.dns_limits.max_candidates || r.dns_limits.max_provenance_bytes))) return false;
  std::set<std::tuple<int32_t, int64_t, uint32_t>> diff, tips;
  for (size_t i = 0; i < r.first_included.size(); ++i) {
    const auto& b = r.first_included[i];
    if (!b.seqno || b.root_hash.empty() || b.file_hash.empty() ||
        (i && b.workchain == -1) ||
        !diff.emplace(b.workchain, b.shard, b.seqno).second) return false;
  }
  for (const auto& b : r.current_tips) {
    if (b.workchain == -1 || b.root_hash.empty() || b.file_hash.empty() ||
        !tips.emplace(b.workchain, b.shard, b.seqno).second) return false;
  }
  const auto distinct = [](const std::vector<std::string>& xs) {
    std::set<std::string> found;
    for (const auto& x : xs) if (x.empty() || !found.insert(x).second) return false;
    return true;
  };
  for (const auto& item : r.reviewed_nft_items) if (!canonical_raw_address(item)) return false;
  for (const auto& item : r.reviewed_dns_items) if (!canonical_raw_address(item)) return false;
  for (char c : r.registry_digest)
    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
  return distinct(r.reviewed_nft_items) && distinct(r.reviewed_dns_items);
}

inline bool listed(const Request& r, const Id& b) {
  return std::any_of(r.first_included.begin(), r.first_included.end(),
                     [&](const Id& x) { return same(x, b); });
}

inline Batch fail(const Request& r, std::string why) {
  Batch out;
  out.provenance = r;
  out.failure = std::move(why);
  out.nft.status = r.enable_nft ? "unresolved" : "not_requested";
  out.dns_sold.status = out.dns_volume.status = r.enable_dns ? "unresolved" : "not_requested";
  out.nft.reason = r.enable_nft ? "batch rejected: " + out.failure : "NFT extraction not requested";
  out.dns_sold.reason = out.dns_volume.reason = r.enable_dns ? "batch rejected: " + out.failure :
                                                                 "DNS extraction not requested";
  return out;
}

// Pure synthetic reducer. Native caller must first verify MC0/full IDs and
// run only selected raw extractors on the SAME immutable ParsedBlock. BoC digests are
// filled by native caller before this method; it never reads current indexes.
inline std::string render_json(const Batch&);

inline Batch reduce(const Request& r, const std::optional<nft_events::Result>& nft,
                    const std::optional<dns::Batch>& dns_batch,
                    std::vector<Fact> nft_facts, std::vector<Fact> dns_facts) {
  if (!valid_request(r)) return fail(r, "invalid network, manifest or explicit registry scope");
  if (nft.has_value() != r.enable_nft || dns_batch.has_value() != r.enable_dns ||
      (!r.enable_nft && !nft_facts.empty()) || (!r.enable_dns && !dns_facts.empty()))
    return fail(r, "disabled extractor ran or enabled extractor missing");
  if ((nft && !nft->ok()) || (dns_batch && !dns_batch->valid))
    return fail(r, "extractor failed: NFT=" + (nft ? nft->error : "not_requested") +
                   "; DNS=" + (dns_batch ? dns_batch->reason : "not_requested"));
  if ((nft && (nft->examined_transactions > r.nft_budget.max_transactions ||
               nft_facts.size() > r.nft_budget.max_candidates)) ||
      (dns_batch && dns_facts.size() > r.dns_limits.max_candidates) ||
      nft_facts.size() + dns_facts.size() > r.max_json_bytes / 64)
    return fail(r, "candidate/transaction/batch byte limit exceeded");
  if ((nft && (!same(from(nft->mc_anchor), r.mc) || nft->candidates.size() != nft_facts.size())) ||
      (dns_batch && dns_batch->candidates.size() != dns_facts.size()))
    return fail(r, "extractor count or full MC ID mismatch");
  auto check = [&](const Fact& f, const std::string& family) {
    return f.family == family && same(f.mc, r.mc) && listed(r, f.source) &&
            canonical_raw_address(f.item) && !f.tx_hash.empty() && f.lt && f.now &&
           !f.state_before.empty() && !f.state_after.empty() && !f.reason.empty() &&
           f.accepted_boc_bytes <= r.max_json_bytes;
  };
  using Key = std::tuple<std::string, std::string, std::string, std::string>;
  std::map<Key, size_t> occurrences;
  std::set<std::tuple<std::string, std::string, std::string, std::string, size_t>> unique;
  for (size_t i = 0; i < nft_facts.size(); ++i) {
    const auto& f = nft_facts[i];
    const auto& c = nft->candidates[i];
    if (!check(f, "nft") || !same(from(c.mc_anchor), r.mc) ||
        !same(from(c.source_block), f.source) || c.account != f.item ||
        c.transaction_hash != f.tx_hash || c.lt != f.lt || c.now != f.now ||
        c.state_hash_before != f.state_before || c.state_hash_after != f.state_after ||
        f.status_before != account_status(c.orig_status) ||
        f.status_after != account_status(c.end_status) ||
        f.signal != "possible_first_initialization" || f.reason != c.reason ||
        f.supplied_init_hash != c.supplied_state_init_hash.value_or("") ||
        f.accepted_init_hash != c.accepted_state_init_hash.value_or("") ||
        (c.accepted_state_init_boc.has_value() != (f.accepted_boc_bytes != 0)) ||
        (c.accepted_state_init_boc &&
         (c.accepted_state_init_boc->size() != f.accepted_boc_bytes || f.accepted_boc_sha256.empty())) ||
        (f.reviewed_item != (std::find(r.reviewed_nft_items.begin(), r.reviewed_nft_items.end(), f.item) !=
                             r.reviewed_nft_items.end())) ||
        f.signal_ordinal != 0 || !f.trigger_message_hash.empty() ||
        !unique.emplace(f.family, f.tx_hash, f.item, f.signal, f.signal_ordinal).second)
      return fail(r, "NFT fact or provenance mismatch");
  }
  for (size_t i = 0; i < dns_facts.size(); ++i) {
    const auto& f = dns_facts[i];
    const auto& c = dns_batch->candidates[i];
    const size_t expected_ordinal = occurrences[Key{"dns", c.tx.hash, c.tx.item_address, signal_name(c.signal)}]++;
    const auto trigger = dns_trigger(c, expected_ordinal);
    if (!trigger) return fail(r, "DNS signal has no distinct triggering message or duplicates logical candidate");
    if (!check(f, "dns") || c.network != r.network ||
        c.zerostate != r.zerostate_root_hash || c.registry_digest != r.registry_digest ||
        !same(from(c.mc_block), r.mc) ||
        !same(from(c.tx.block), f.source) || c.tx.item_address != f.item ||
        c.tx.hash != f.tx_hash || c.tx.lt != f.lt || c.tx.now != f.now ||
        c.tx.state_hash_before != f.state_before || c.tx.state_hash_after != f.state_after ||
        c.tx.aborted != f.aborted || f.reason != c.reason || f.signal != signal_name(c.signal) ||
        f.signal_ordinal != expected_ordinal || f.trigger_message_hash != *trigger ||
        f.messages.size() !=
        c.tx.outgoing.size() + static_cast<size_t>(c.tx.incoming.has_value()) ||
        std::find(r.reviewed_dns_items.begin(), r.reviewed_dns_items.end(), f.item) == r.reviewed_dns_items.end() ||
        !f.reviewed_item ||
        !unique.emplace(f.family, f.tx_hash, f.item, f.signal, f.signal_ordinal).second)
      return fail(r, "DNS fact or provenance mismatch");
    const auto message_same = [](const dns::Message& a, const dns::Message& b) {
      return a.hash == b.hash && a.source == b.source && a.destination == b.destination &&
             a.opcode == b.opcode && a.value_nanoton == b.value_nanoton && a.bounced == b.bounced;
    };
    size_t offset = 0;
    if (c.tx.incoming) {
      if (!message_same(f.messages[0], *c.tx.incoming)) return fail(r, "DNS inbound message mismatch");
      offset = 1;
    }
    for (size_t j = 0; j < c.tx.outgoing.size(); ++j)
      if (!message_same(f.messages[j + offset], c.tx.outgoing[j]))
        return fail(r, "DNS outbound message mismatch");
  }
  Batch out;
  out.valid = true;
  out.provenance = r;
  out.nft_fact_count = nft_facts.size();
  out.dns_fact_count = dns_facts.size();
  out.nft_examined_transactions = nft ? nft->examined_transactions : 0;
  if (!r.enable_nft) { out.nft.status = "not_requested"; out.nft.reason = "NFT extraction not requested"; }
  if (!r.enable_dns) {
    out.dns_sold.status = out.dns_volume.status = "not_requested";
    out.dns_sold.reason = out.dns_volume.reason = "DNS extraction not requested";
  }
  out.facts.reserve(nft_facts.size() + dns_facts.size());
  for (auto& f : nft_facts) out.facts.push_back(std::move(f));
  for (auto& f : dns_facts) out.facts.push_back(std::move(f));
  try { (void)render_json(out); }
  catch (const std::length_error&) { return fail(r, "serialized fact batch exceeds 256 KiB"); }
  return out;
}

// Header-only serializer keeps offline reducer tests independent of generated
// TON TL-B headers. It never truncates: even one oversized field rejects scope.
namespace detail {
inline void quote(std::string& out, const std::string& value, size_t cap) {
  static constexpr char hex[] = "0123456789abcdef";
  if (out.size() >= cap) throw std::length_error("assets event JSON budget exceeded");
  out += '"';
  for (unsigned char c : value) {
    if (out.size() + 6 > cap) throw std::length_error("assets event JSON budget exceeded");
    if (c == '"' || c == '\\') { out += '\\'; out += static_cast<char>(c); }
    else if (c < 0x20 || c >= 0x7f) {
      out += "\\u00"; out += hex[c >> 4]; out += hex[c & 15];
    } else out += static_cast<char>(c);
  }
  out += '"';
}
inline void block(std::string& out, const Id& id, size_t cap) {
  out += "{\"workchain\":" + std::to_string(id.workchain) + ",\"shard\":" +
         std::to_string(id.shard) + ",\"seqno\":" + std::to_string(id.seqno) + ",\"root_hash\":";
  quote(out, id.root_hash, cap); out += ",\"file_hash\":"; quote(out, id.file_hash, cap); out += '}';
}
inline void message(std::string& out, const dns::Message& msg, size_t cap) {
  out += "{\"hash\":"; quote(out, msg.hash, cap);
  const auto optional = [&](const char* key, const std::optional<std::string>& v) {
    out += ",\""; out += key; out += "\":";
    if (v) quote(out, *v, cap); else out += "null";
  };
  optional("source", msg.source); optional("destination", msg.destination);
  optional("value_nanoton", msg.value_nanoton);
  out += ",\"opcode\":"; out += msg.opcode ? std::to_string(*msg.opcode) : "null";
  out += ",\"bounced\":";
  out += msg.bounced ? (*msg.bounced ? "true" : "false") : "null";
  out += '}';
}
} // namespace detail

inline std::string render_json(const Batch& b) {
  const size_t cap = std::min(b.provenance.max_json_bytes, kMaxBatchBytes);
  if (!cap) throw std::length_error("zero assets event JSON budget");
  const auto& r = b.provenance;
  if (b.valid && (!valid_request(r) || b.nft_fact_count + b.dns_fact_count != b.facts.size()))
    throw std::invalid_argument("invalid event fact count or provenance");
  std::string out = "{\"dataset\":\"assets_event_candidates\",\"scope\":\"first_included_diff_subset\",\"network\":";
  const auto field = [&](const char* key, const std::string& v) {
    out += ",\""; out += key; out += "\":"; detail::quote(out, v, cap);
  };
  detail::quote(out, r.network, cap);
  field("zerostate_root_hash", r.zerostate_root_hash);
  field("zerostate_file_hash", r.zerostate_file_hash);
  field("calc_version", r.calc_version);
  field("registry_digest", r.registry_digest);
  out += ",\"mc_full_id\":"; detail::block(out, r.mc, cap);
  out += ",\"enable_nft\":"; out += r.enable_nft ? "true" : "false";
  out += ",\"enable_dns\":"; out += r.enable_dns ? "true" : "false";
  const auto ids = [&](const char* key, const std::vector<Id>& values) {
    out += ",\""; out += key; out += "\":[";
    for (size_t i = 0; i < values.size(); ++i) {
      if (i) out += ',';
      detail::block(out, values[i], cap);
    }
    out += ']';
  };
  ids("first_included", r.first_included); ids("current_tips", r.current_tips);
  const auto addresses = [&](const char* key, const std::vector<std::string>& values) {
    out += ",\""; out += key; out += "\":[";
    for (size_t i = 0; i < values.size(); ++i) {
      if (i) out += ',';
      detail::quote(out, values[i], cap);
    }
    out += ']';
  };
  addresses("reviewed_nft_items", r.reviewed_nft_items);
  addresses("reviewed_dns_items", r.reviewed_dns_items);
  out += ",\"valid\":"; out += b.valid ? "true" : "false";
  out += ",\"failure\":";
  if (b.failure.empty()) out += "null"; else detail::quote(out, b.failure, cap);
  out += ",\"snapshot_integrity_checked\":"; out += b.snapshot_integrity_checked ? "true" : "false";
  out += ",\"diff_exhaustiveness_checked\":"; out += b.diff_exhaustiveness_checked ? "true" : "false";
  out += ",\"examined_nft_transactions\":" + std::to_string(b.nft_examined_transactions);
  out += ",\"fact_count\":" + std::to_string(b.facts.size());
  out += ",\"nft_fact_count\":" + std::to_string(b.nft_fact_count);
  out += ",\"dns_fact_count\":" + std::to_string(b.dns_fact_count);
  out += ",\"facts\":[";
  for (size_t i = 0; i < b.facts.size(); ++i) {
    const auto& f = b.facts[i];
    if (i) out += ',';
    out += "{\"family\":"; detail::quote(out, f.family, cap);
    field("signal", f.signal); field("item", f.item);
    out += ",\"signal_ordinal\":" + std::to_string(f.signal_ordinal);
    out += ",\"trigger_message_hash\":";
    if (f.trigger_message_hash.empty()) out += "null"; else detail::quote(out, f.trigger_message_hash, cap);
    out += ",\"reviewed_item\":"; out += f.reviewed_item ? "true" : "false";
    out += ",\"mc_full_id\":"; detail::block(out, f.mc, cap);
    out += ",\"source_full_id\":"; detail::block(out, f.source, cap);
    field("raw_tx_hash", f.tx_hash);
    out += ",\"raw_tx_lt\":" + std::to_string(f.lt);
    out += ",\"raw_tx_now\":" + std::to_string(f.now);
    field("state_before", f.state_before); field("state_after", f.state_after);
    const auto optional = [&](const char* key, const std::string& value) {
      out += ",\""; out += key; out += "\":";
      if (value.empty()) out += "null"; else detail::quote(out, value, cap);
    };
    optional("status_before", f.status_before); optional("status_after", f.status_after);
    field("reason", f.reason);
    optional("supplied_state_init_hash", f.supplied_init_hash);
    optional("accepted_state_init_hash", f.accepted_init_hash);
    optional("accepted_boc_sha256", f.accepted_boc_sha256);
    out += ",\"accepted_boc_bytes\":" + std::to_string(f.accepted_boc_bytes);
    out += ",\"aborted\":"; out += f.aborted ? "true" : "false";
    out += ",\"messages\":[";
    for (size_t j = 0; j < f.messages.size(); ++j) {
      if (j) out += ',';
      detail::message(out, f.messages[j], cap);
    }
    out += "]}";
    if (out.size() > cap) throw std::length_error("assets event JSON budget exceeded");
  }
  const auto metric = [&](const Metric& m) {
    out += "{\"metric\":"; detail::quote(out, m.name, cap);
    out += ",\"status\":"; detail::quote(out, m.status, cap);
    out += ",\"value\":null,\"reason\":"; detail::quote(out, m.reason, cap);
    out += ",\"ready\":false}";
  };
  out += "],\"metrics\":[";
  metric(b.nft); out += ','; metric(b.dns_sold); out += ','; metric(b.dns_volume);
  out += "],\"daily_complete\":false,\"lifetime_complete\":false,\"writer_committed\":false,\"publication_ready\":false}";
  if (out.size() > cap) throw std::length_error("assets event JSON budget exceeded");
  return out;
}

// Owns no parser/anchor references after return. A failed scope has zero facts.
Batch extract(const ParsedBlock&, const tonstat::core::AnchorEvidence&, const Request&);
// Throws std::length_error instead of truncating; exactly one fact per emitted
// candidate signal, with counts and explicit null metric values.

} // namespace assets_analytics::event_stage
