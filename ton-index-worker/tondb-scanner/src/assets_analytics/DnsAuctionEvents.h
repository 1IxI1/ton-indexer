#pragma once

#include <cstddef>
#include <cstdint>
#include <charconv>
#include <limits>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

struct ParsedBlock;

namespace assets_analytics::dns {

// These are producer-only observations, NEVER sale facts or a coverage certificate.
// Callers must pass explicit DNS item addresses from a separately reviewed registry.
// No getter, current-state lookup, NodeDB, writer or publication is performed here.
struct BlockId {
  int32_t workchain{0};
  int64_t shard{0};
  uint32_t seqno{0};
  std::string root_hash;  // 32-byte hash in the parser's base64 representation
  std::string file_hash;
};

// TON td::Bits256::to_hex() may render uppercase. Canonicalize only a typed
// standard address's 256-bit hex payload, never arbitrary account strings.
// Invalid length/characters are an error, not a silently unmatched address.
inline std::optional<std::string> canonical_account_address(int32_t workchain, std::string hex) {
  if (hex.size() != 64) return std::nullopt;
  for (char& c : hex) {
    if (c >= 'A' && c <= 'F') c = static_cast<char>(c - 'A' + 'a');
    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return std::nullopt;
  }
  return std::to_string(workchain) + ":" + hex;
}

struct Message {
  std::string hash;
  std::optional<std::string> source;
  std::optional<std::string> destination;
  std::optional<uint32_t> opcode;
  std::optional<std::string> value_nanoton;  // decimal integer; null != zero (external message)
  std::optional<bool> bounced;
};

struct Tx {
  BlockId block;
  std::string item_address;
  std::string hash;
  uint64_t lt{0};
  uint32_t now{0};
  uint32_t mc_seqno{0};
  std::string state_hash_before;
  std::string state_hash_after;
  bool was_active{false};
  bool is_active{false};
  bool aborted{false};
  std::optional<Message> incoming;
  std::vector<Message> outgoing;
  // Optional caller-supplied triage ONLY, tied to this tx's historical pre-state.
  // Never populated by the native ParsedBlock adapter; not a sale proof.
  std::optional<uint64_t> auction_end_before_hint;
  std::optional<std::string> auction_hint_state_hash;
};

enum class Signal {
  first_auction_candidate,  // first *deploy* is not first sale or necessarily first lifetime deploy
  bid_candidate,            // includes outbid/refund; gross inbound value is NOT volume
  refund_candidate,
  expiry_candidate,         // a time condition, NOT an on-chain sale
  settlement_candidate,     // fill_up attempt; delivery and state transition unverified
  release_reauction_candidate,
  secondary_transfer_candidate, // transfer may also settle on the same tx
  other_item_transaction
};

struct Candidate {
  Signal signal;
  Tx tx;
  std::string network;
  std::string zerostate;
  BlockId mc_block;
  std::string registry_digest;
  std::string reason{"unresolved: historical pre/post auction state, collection/code version, "
                     "lifetime history and settlement transition not verified"};
  // Intentionally NO sold count, winning bid or volume field. These signals
  // cannot be reduced to numeric primary-sale metrics, including zero.
};

struct Limits {
  size_t max_addresses{0};
  size_t max_blocks{0};
  size_t max_transactions{0};
  size_t max_messages_per_tx{0};
  size_t max_total_messages{0};
  size_t max_candidates{0};
  size_t max_provenance_bytes{0}; // also bounds total original diff BoC bytes hashed by native adapter
};

struct Request {
  std::string network;
  std::string zerostate;
  BlockId mc_block;
  std::string registry_digest;
  std::vector<std::string> item_addresses;
  Limits limits;
};

struct Batch {
  bool valid{false};
  std::string reason;
  std::vector<Candidate> candidates;
  static constexpr bool first_sale_complete = false;
  static constexpr bool volume_complete = false;
};

inline bool valid_base64_hash(const std::string& s) {
  if (s.size() != 44 || s.back() != '=') return false;
  for (size_t i = 0; i < 43; ++i) {
    char c = s[i];
    if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
          (c >= '0' && c <= '9') || c == '+' || c == '/')) return false;
  }
  return true;
}

inline bool same_ordered_diff(const std::vector<BlockId>& parsed_ids,
                              const std::vector<BlockId>& diff_ids, const BlockId& mc) {
  if (parsed_ids.empty() || parsed_ids.size() != diff_ids.size()) return false;
  size_t mc_count = 0;
  std::set<std::string> coordinates;
  for (size_t i = 0; i < diff_ids.size(); ++i) {
    const auto& a = parsed_ids[i];
    const auto& b = diff_ids[i];
    if (!b.seqno || !valid_base64_hash(b.root_hash) || !valid_base64_hash(b.file_hash) ||
        !coordinates.insert(std::to_string(b.workchain) + ":" + std::to_string(b.shard) +
                            ":" + std::to_string(b.seqno)).second) return false;
    if (a.workchain != b.workchain || a.shard != b.shard || a.seqno != b.seqno ||
        a.root_hash != b.root_hash || a.file_hash != b.file_hash) return false;
    if (b.workchain == -1) {
      ++mc_count;
      if (i != 0 || b.workchain != mc.workchain || b.shard != mc.shard ||
          b.seqno != mc.seqno || b.root_hash != mc.root_hash || b.file_hash != mc.file_hash)
        return false;
    }
  }
  return mc_count == 1;
}

inline bool tx_within_source_block(uint64_t lt, uint32_t now, uint64_t start_lt,
                                    uint64_t end_lt, int32_t gen_utime) {
  return gen_utime > 0 && start_lt < end_lt && lt >= start_lt && lt < end_lt &&
         now == static_cast<uint32_t>(gen_utime);
}

// Pure decision boundary for offline tests. Input MUST be first-included blocks
// only; it does not infer block coverage from a repeating shard tip. Any missing,
// duplicate or over-budget provenance invalidates the entire batch, not a subset.
inline Batch extract_from_first_included(const std::vector<Tx>& transactions, const Request& request,
                                         const std::vector<BlockId>& included_blocks) {
  auto fail = [](const char* reason) { Batch b; b.reason = reason; return b; };
  const auto hex64 = [](const std::string& s) {
    if (s.size() != 64) return false;
    for (char c : s) if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
                          (c >= 'A' && c <= 'F'))) return false;
    return true;
  };
  const auto block_ok = [&](const BlockId& id) {
    return id.seqno && valid_base64_hash(id.root_hash) && valid_base64_hash(id.file_hash);
  };
  const auto address_ok = [&](const std::string& s) {
    if (s.size() > 76) return false;
    auto colon = s.find(':');
    if (colon == std::string::npos || colon == 0 || colon > 11 ||
        !hex64(s.substr(colon + 1))) return false;
    size_t start = s[0] == '-' ? 1 : 0;
    if (start == colon) return false;
    for (size_t i = start; i < colon; ++i) if (s[i] < '0' || s[i] > '9') return false;
    int32_t wc = 0;
    auto parsed = std::from_chars(s.data(), s.data() + colon, wc);
    if (parsed.ec != std::errc{} || parsed.ptr != s.data() + colon ||
        std::to_string(wc) != s.substr(0, colon)) return false;
    return true;
  };
  const auto value_ok = [](const std::optional<std::string>& value) {
    if (!value) return true;
    if (value->empty() || value->size() > 78) return false; // signed 256-bit bound
    for (char c : *value) if (c < '0' || c > '9') return false;
    return true;
  };
  const auto message_ok = [&](const Message& m) {
    return hex64(m.hash) && (!m.source || address_ok(*m.source)) &&
           (!m.destination || address_ok(*m.destination)) && value_ok(m.value_nanoton) &&
           (!m.source || !m.destination || m.value_nanoton.has_value());
  };
  const auto same_id = [](const BlockId& a, const BlockId& b) {
    return a.workchain == b.workchain && a.shard == b.shard && a.seqno == b.seqno &&
           a.root_hash == b.root_hash && a.file_hash == b.file_hash;
  };
  const Limits& cap = request.limits;
  // Hard ceilings prevent an accidental "unbounded" caller budget.
  if (cap.max_addresses > 4096 || cap.max_blocks > 4096 || cap.max_transactions > 10000 ||
      cap.max_messages_per_tx > 256 || cap.max_candidates > 50000 ||
      cap.max_total_messages > 50000 ||
      cap.max_provenance_bytes > 64U * 1024U * 1024U)
    return fail("hard extraction ceiling exceeded");
  if (!cap.max_addresses || !cap.max_blocks || !cap.max_transactions ||
      !cap.max_messages_per_tx || !cap.max_total_messages || !cap.max_candidates ||
      !cap.max_provenance_bytes ||
      request.item_addresses.empty() || request.item_addresses.size() > cap.max_addresses ||
      included_blocks.empty() || included_blocks.size() > cap.max_blocks ||
      transactions.size() > cap.max_transactions) return fail("empty scope or resource limit exceeded");
  if (request.network.empty() || request.network.size() > 128 || request.zerostate.empty() ||
      request.zerostate.size() > 256 || !hex64(request.registry_digest) ||
      request.mc_block.workchain != -1 ||
      request.mc_block.shard != std::numeric_limits<int64_t>::min() ||
      !block_ok(request.mc_block)) return fail("missing or malformed registry/MC provenance");
  std::set<std::string> addresses;
  for (const auto& address : request.item_addresses) {
    // Parser/StdAddress render raw hashes in lowercase; other spellings would
    // silently miss an address and must not be mistaken for a covered scope.
    if (!address_ok(address) || address.find_first_of("ABCDEF", address.find(':') + 1) != std::string::npos ||
        !addresses.insert(address).second)
      return fail("invalid or duplicate explicit DNS item address");
  }
  Batch batch;
  size_t used_bytes = 0;
  std::set<std::string> tx_hashes;
  std::map<std::string, BlockId> blocks;
  const auto coordinate = [](const BlockId& id) {
    return std::to_string(id.workchain) + ":" + std::to_string(id.shard) +
           ":" + std::to_string(id.seqno);
  };
  bool found_mc = false;
  for (const BlockId& id : included_blocks) {
    if (!block_ok(id) || !blocks.emplace(coordinate(id), id).second)
      return fail("missing or duplicate first-included block provenance");
    if (id.workchain == -1) {
      if (found_mc || !same_id(id, request.mc_block))
        return fail("MC full block ID mismatch");
      found_mc = true;
    }
  }
  if (!found_mc) return fail("MC block missing from first-included manifest");
  size_t message_count = 0;
  for (const Tx& tx : transactions) {
    if (!block_ok(tx.block) || !hex64(tx.hash) || !hex64(tx.state_hash_before) ||
        !hex64(tx.state_hash_after) || !address_ok(tx.item_address) ||
        tx.item_address.rfind(std::to_string(tx.block.workchain) + ":", 0) != 0 ||
        canonical_account_address(tx.block.workchain, tx.item_address.substr(tx.item_address.find(':') + 1)) !=
            tx.item_address ||
        !tx.lt || !tx.now ||
        tx.mc_seqno != request.mc_block.seqno ||
        (tx.block.workchain == -1 && !same_id(tx.block, request.mc_block)) ||
        tx.outgoing.size() > cap.max_messages_per_tx ||
        (tx.incoming && !message_ok(*tx.incoming)))
      return fail("missing or mismatched transaction provenance");
    const size_t n_messages = tx.outgoing.size() + static_cast<size_t>(tx.incoming.has_value());
    if (n_messages > cap.max_total_messages - message_count)
      return fail("aggregate message limit exceeded");
    message_count += n_messages;
    for (const auto& m : tx.outgoing) if (!message_ok(m))
      return fail("missing or malformed outgoing message provenance");
    if (!tx_hashes.insert(tx.hash).second) return fail("duplicate transaction in first-included set");
    auto listed = blocks.find(coordinate(tx.block));
    if (listed == blocks.end() || !same_id(listed->second, tx.block))
      return fail("transaction block not in first-included manifest");
    if (tx.auction_end_before_hint &&
        (!tx.auction_hint_state_hash || *tx.auction_hint_state_hash != tx.state_hash_before))
      return fail("expiry hint not bound to transaction pre-state hash");
    if (tx.auction_hint_state_hash && !hex64(*tx.auction_hint_state_hash))
      return fail("invalid expiry hint state hash");
    if (addresses.count(tx.item_address) == 0) continue;

    std::vector<Signal> signals;
    if (!tx.was_active && tx.is_active && tx.incoming)
      signals.push_back(Signal::first_auction_candidate);
    if (tx.incoming && !tx.aborted && tx.incoming->bounced != true &&
        (!tx.incoming->opcode || *tx.incoming->opcode == 0) && tx.incoming->value_nanoton)
      signals.push_back(Signal::bid_candidate);
    if (tx.auction_end_before_hint && tx.now > *tx.auction_end_before_hint)
      signals.push_back(Signal::expiry_candidate);
    if (tx.incoming && tx.incoming->opcode == 0x4ed14b65U)
      signals.push_back(Signal::release_reauction_candidate);
    if (tx.incoming && tx.incoming->opcode == 0x5fcc3d14U)
      signals.push_back(Signal::secondary_transfer_candidate);
    for (const auto& out : tx.outgoing) {
      if (out.opcode == 0x557cea20U) signals.push_back(Signal::refund_candidate);
      if (out.opcode == 0x370fec51U) signals.push_back(Signal::settlement_candidate);
    }
    if (signals.empty()) signals.push_back(Signal::other_item_transaction);
    // Each output owns its complete tx/message provenance. Charge all copies,
    // including repeated metadata and fixed object storage, before allocating.
    size_t bytes = sizeof(Candidate) + tx.item_address.size() + tx.hash.size() +
                   tx.state_hash_before.size() + tx.state_hash_after.size() +
                   tx.block.root_hash.size() + tx.block.file_hash.size() +
                   request.mc_block.root_hash.size() + request.mc_block.file_hash.size() +
                   request.network.size() + request.zerostate.size() + request.registry_digest.size() + 256;
    const auto add_message = [&](const Message& m) {
      bytes += sizeof(Message) + m.hash.size() +
               (m.source ? m.source->size() : 0) +
               (m.destination ? m.destination->size() : 0) +
               (m.value_nanoton ? m.value_nanoton->size() : 0);
    };
    if (tx.incoming) add_message(*tx.incoming);
    for (const auto& m : tx.outgoing) add_message(m);
    if (tx.auction_hint_state_hash) bytes += tx.auction_hint_state_hash->size();
    for (Signal signal : signals) {
      if (batch.candidates.size() >= cap.max_candidates ||
          bytes > cap.max_provenance_bytes - used_bytes)
        return fail("candidate or aggregate provenance byte limit exceeded");
      used_bytes += bytes;
      batch.candidates.push_back({signal, tx, request.network, request.zerostate,
                                  request.mc_block, request.registry_digest});
    }
  }
  batch.valid = true;
  return batch;
}

// Native adapter: ONLY ParsedBlock.blocks_ (MC + shard DIFF), never shard_blocks_
// current tips or account_interfaces_ (post-state / current metadata).
Batch extract_dns_auction_candidates(const ParsedBlock& parsed, const Request& request);

}  // namespace assets_analytics::dns
