#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <set>
#include <string>
#include <tuple>
#include <vector>

struct ParsedBlock;

namespace assets_analytics::nft_events {

// This is a producer of raw, per-transaction leads, NOT a minted-NFT classifier.
// Hashes of blocks are the base64 hashes emitted by DataParser; transaction and
// account-state hashes below are hex. The caller must supply the exact MC anchor.
struct BlockId {
  int32_t workchain{};
  int64_t shard{};
  uint32_t seqno{};
  std::string root_hash;
  std::string file_hash;
};

// StdAddress::addr.to_hex() uses uppercase in the native adapter, whereas
// reviewed-item manifests use canonical lowercase raw workchain:64-hex.
// Validate the full 256-bit address and retain the signed workchain so the
// same account bits in different workchains never alias.
inline std::optional<std::string> canonical_account_address(int32_t workchain, std::string hex) {
  if (hex.size() != 64) return std::nullopt;
  for (char& c : hex) {
    if (c >= 'A' && c <= 'F') c = static_cast<char>(c - 'A' + 'a');
    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return std::nullopt;
  }
  return std::to_string(workchain) + ":" + hex;
}

struct Budget {
  size_t max_blocks{};
  size_t max_transactions{};
  size_t max_candidates{};
  size_t max_evidence_bytes{};
};

inline bool same_block(const BlockId& a, const BlockId& b) {
  return std::tie(a.workchain, a.shard, a.seqno, a.root_hash, a.file_hash) ==
         std::tie(b.workchain, b.shard, b.seqno, b.root_hash, b.file_hash);
}

// A source is accepted only when the parser's blocks are identical, in order,
// to the supplied first-included diff. Repeated tips do not
// belong in this manifest. This does NOT prove the diff covers all ancestry.
inline bool valid_diff_layout(const BlockId& mc, const std::vector<BlockId>& blocks,
                              const std::vector<BlockId>& diff, Budget budget) {
  if (mc.workchain != -1 || !mc.seqno || mc.root_hash.empty() || mc.file_hash.empty() ||
      !budget.max_blocks || !budget.max_transactions || !budget.max_candidates ||
      !budget.max_evidence_bytes || blocks.empty() || blocks.size() > budget.max_blocks ||
      blocks.size() != diff.size() || !same_block(blocks.front(), mc)) return false;
  std::set<std::tuple<int32_t, int64_t, uint32_t>> seen;
  for (size_t i = 0; i < blocks.size(); ++i) {
    const auto& b = blocks[i];
    if (b.root_hash.empty() || b.file_hash.empty() || !b.seqno || !same_block(b, diff[i]) ||
        (i && b.workchain == -1) || !seen.emplace(b.workchain, b.shard, b.seqno).second)
      return false;
  }
  return true;
}

enum class Status { nonexist, uninit, frozen, active };

struct Signal {
  Status before;
  Status after;
  bool committed{};             // successful compute AND non-aborted transaction
  bool state_changed{};         // account-cell hashes differ (NOT NFT init)
};

enum class Decision { not_candidate, possible_first_initialization };

// No getter, current index or account's last state participates in this decision.
// In particular active->active may initialize an already deployed item.
inline Decision decide(const Signal& s) {
  return s.committed && s.after == Status::active && s.state_changed
             ? Decision::possible_first_initialization
             : Decision::not_candidate;
}

struct OrderedTx {
  std::string account;
  std::string hash;
  uint64_t lt{};
  uint64_t prev_lt{};
  std::string prev_hash;
  std::string before_hash;
  std::string after_hash;
  Status before{};
  Status after{};
};

// Used only for consecutive transactions of ONE address in ONE source block.
// Different blocks in the diff may be enumerated in a different order.
inline bool contiguous(const OrderedTx& previous, const OrderedTx& next) {
  return previous.account == next.account && next.lt > previous.lt &&
         next.prev_lt == previous.lt && next.prev_hash == previous.hash &&
         next.before_hash == previous.after_hash && next.before == previous.after;
}

inline bool bounded_add(size_t bytes, size_t& used, size_t cap) {
  if (used > cap || bytes > cap - used) return false;
  used += bytes;
  return true;
}

inline bool bounded_count(size_t count, size_t& used, size_t cap) {
  return bounded_add(count, used, cap);
}

struct Candidate {
  BlockId source_block;
  BlockId mc_anchor;
  std::string account;               // raw workchain:hex address
  std::string transaction_hash;      // raw transaction cell hash (hex)
  uint64_t lt{};
  uint32_t now{};
  Status orig_status{};
  Status end_status{};
  std::string state_hash_before;
  std::string state_hash_after;
  std::optional<std::string> supplied_state_init_hash; // incoming, not necessarily accepted
  std::optional<std::string> accepted_state_init_hash;
  // Binary CRC32C BoC, decoded from DataParser's base64 init_state_boc after
  // binding to the raw transaction's StateInit. Not decoded NFT data.
  std::optional<std::string> accepted_state_init_boc;
  std::string reason;              // status transition or active-state change only
  // NEVER infer minted from this candidate: historical pre/post get_nft_data.init,
  // collection verification (if applicable), and lifetime coverage are absent.
};

inline bool candidate_less(const Candidate& a, const Candidate& b) {
  return std::tie(a.lt, a.account, a.transaction_hash) <
         std::tie(b.lt, b.account, b.transaction_hash);
}

struct Result {
  BlockId mc_anchor;
  std::vector<Candidate> candidates; // sorted by (LT, address, tx hash)
  size_t examined_transactions{};
  std::string error;                  // nonempty => entire batch invalid, no candidates
  bool ok() const { return error.empty(); }
  static constexpr bool minted_verified = false;
  static constexpr bool lifetime_complete = false;
};

// Read-only and synchronous. blocks_ must be the *entire*, ordered parsed
// shard_blocks_diff_ (including one MC); shard_blocks_ are NOT event inputs.
// Fails closed as one invalid batch, never silently returns an empty success
// after a missing block, hash, malformed tx or exceeded cap. Does no DB/getter I/O.
Result extract(const ParsedBlock& parsed, const BlockId& expected_mc, Budget budget);

}  // namespace assets_analytics::nft_events
