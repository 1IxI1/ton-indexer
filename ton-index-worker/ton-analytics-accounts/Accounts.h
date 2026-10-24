#pragma once

#include <algorithm>
#include <cstdint>
#include <limits>
#include <map>
#include <set>
#include <stdexcept>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

namespace tonstat::accounts {

// No balance augmentation, CH latest-account table, or sampled result can create this baseline.
enum class Status : unsigned char { nonexist = 3, uninit = 0, frozen = 1, active = 2 };
enum class Readiness { incomplete, complete };

struct Counts {
  std::uint64_t uninit = 0, active = 0, frozen = 0;
  std::uint64_t total() const {
    if (uninit > UINT64_MAX - active || uninit + active > UINT64_MAX - frozen)
      throw std::overflow_error("account total overflow");
    return uninit + active + frozen;
  }
  bool operator==(const Counts&) const = default;
};

inline std::uint64_t& component(Counts& c, Status s) {
  switch (s) {
    case Status::uninit: return c.uninit;
    case Status::active: return c.active;
    case Status::frozen: return c.frozen;
    default: throw std::invalid_argument("nonexist has no count");
  }
}

inline void transition(Counts& c, Status before, Status after) {
  if (before == after) return;
  if (before != Status::nonexist && component(c, before) == 0)
    throw std::runtime_error("status count underflow");
  if (after != Status::nonexist && component(c, after) == UINT64_MAX)
    throw std::overflow_error("status count overflow");
  if (before != Status::nonexist) --component(c, before);
  if (after != Status::nonexist) ++component(c, after);
  (void)c.total();
}

struct BlockId {
  std::int32_t workchain = 0;
  std::uint64_t shard = 0;
  std::uint32_t seqno = 0;
  std::string root_hash, file_hash;  // full hashes, never just wc/shard/seqno
  auto tie() const { return std::tie(workchain, shard, seqno, root_hash, file_hash); }
  bool operator<(const BlockId& rhs) const { return tie() < rhs.tie(); }
  bool operator==(const BlockId& rhs) const { return tie() == rhs.tie(); }
};

inline bool hex64(const std::string& x) {
  return x.size() == 64 && std::all_of(x.begin(), x.end(), [](unsigned char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
  });
}

inline void require_id(const BlockId& id) {
  if (!hex64(id.root_hash) || !hex64(id.file_hash))
    throw std::invalid_argument("missing full block hashes");
}

struct Tip {
  BlockId id;
  std::string state_root;  // state root representation hash, distinct from block root
  bool operator==(const Tip&) const = default;
};

struct Anchor {
  std::string network, zerostate; // explicit network identity
  BlockId mc;
  std::string mc_state_root;
  std::vector<Tip> tips; // includes MC and every top shard, no intermediate states
};

inline void require_anchor(const Anchor& a) {
  if (a.network.empty() || !hex64(a.zerostate) || !hex64(a.mc_state_root) ||
      a.mc.workchain != -1 || a.tips.empty())
    throw std::invalid_argument("incomplete anchor identity");
  require_id(a.mc);
  std::set<BlockId> seen;
  bool found_mc = false;
  for (const auto& t : a.tips) {
    require_id(t.id);
    if (!hex64(t.state_root) || !seen.insert(t.id).second)
      throw std::invalid_argument("invalid or repeated snapshot tip");
    if (t.id.workchain == -1) {
      if (!(t.id == a.mc) || t.state_root != a.mc_state_root || found_mc)
        throw std::invalid_argument("MC state mismatch");
      found_mc = true;
    }
  }
  if (!found_mc) throw std::invalid_argument("MC tip missing");
}

struct Snapshot {
  Anchor anchor;
  Counts counts; // diagnostic lower bound ONLY when incomplete; never a published total
  std::uint64_t visited = 0;
  std::size_t scanned_tips = 0;
  Readiness readiness = Readiness::incomplete;
  std::string reason = "not scanned";
};

// Independent, testable gate; native scan must attest ALL MC shard-config tips, not
// merely that the list it happened to receive was exhausted.
inline void finish_snapshot(Snapshot& s, bool approved_full_scan, bool tip_manifest_checked) {
  require_anchor(s.anchor);
  if (approved_full_scan && tip_manifest_checked && s.scanned_tips == s.anchor.tips.size()) {
    if (s.counts.total() != s.visited)
      throw std::runtime_error("snapshot visit/count mismatch (nonexist record?)");
    s.readiness = Readiness::complete;
    s.reason.clear();
  } else {
    s.readiness = Readiness::incomplete;
    s.reason = !approved_full_scan ? "bounded sample; full scan not approved" :
               !tip_manifest_checked ? "MC tip manifest not verified" : "tips not exhausted";
  }
}

struct AccountKey {
  std::int32_t workchain;
  std::string address; // 64 hex digits from raw transaction account_addr
  auto tie() const { return std::tie(workchain, address); }
  bool operator<(const AccountKey& rhs) const { return tie() < rhs.tie(); }
};

struct Tx {
  AccountKey account;
  std::uint64_t lt;
  std::string hash;
  Status before, after;
  std::uint64_t prev_lt = 0;
  std::string prev_hash;
  std::string old_state_hash, new_state_hash;
};

struct AccountWitness {
  Status status;
  std::uint64_t last_lt;
  std::string last_hash, state_hash;
};

struct NewBlock {
  BlockId id;
  std::vector<BlockId> prev; // native unpack_block_prev_blk_ext, full hashes
  std::vector<Tx> transactions; // every raw AccountBlock/Transaction; sorted below
  std::string old_state_hash, post_state_hash; // from raw update and fetched state
};

struct Step {
  Anchor next;
  BlockId previous_mc;
  std::vector<NewBlock> newly_included; // complete MC + shard diff, not recurring tips
  // Only the native adapter may set this after checking the MC shard config,
  // first-inclusion manifest, raw prev references, and state roots.
  bool inclusion_and_topology_verified = false;
  bool raw_identity_verified = false;
  bool state_linkage_verified = false;
  // A separate read-only snapshot-account lookup must authenticate EACH first
  // touched address against the baseline root. Native.cpp currently cannot.
  bool baseline_witnesses_verified = false;
  std::map<AccountKey, AccountWitness> baseline_witnesses;
  std::string pending_reason;
};

struct Caps {
  std::size_t max_blocks = 256, max_transactions = 100000,
              max_tracked_accounts = 100000, max_boc_bytes = 16 * 1024 * 1024,
              max_snapshot_tips = 1024;
};

// Atomic per-step application; a bad block never advances the published cursor.
class Counter {
 public:
  explicit Counter(Snapshot baseline, Caps caps = {}) : current_(std::move(baseline)), caps_(caps) {
    require_anchor(current_.anchor);
    if (!caps_.max_blocks || !caps_.max_transactions || !caps_.max_tracked_accounts ||
        !caps_.max_boc_bytes || !caps_.max_snapshot_tips)
      throw std::invalid_argument("zero delta cap");
  }
  const Snapshot& current() const { return current_; }

  void apply(const Step& step) {
    require_anchor(step.next);
    if (current_.readiness != Readiness::complete || !step.inclusion_and_topology_verified ||
        !step.raw_identity_verified ||
        !step.state_linkage_verified || !step.baseline_witnesses_verified ||
        step.previous_mc != current_.anchor.mc ||
        step.next.network != current_.anchor.network || step.next.zerostate != current_.anchor.zerostate ||
        step.next.mc.seqno != current_.anchor.mc.seqno + 1)
      throw std::runtime_error("unverified or non-contiguous accounts transition");
    if (step.newly_included.size() > caps_.max_blocks ||
        step.baseline_witnesses.size() > caps_.max_tracked_accounts)
      throw std::runtime_error("delta budget exceeded");
    std::size_t tx_count = 0;
    for (const auto& b : step.newly_included) {
      if (b.transactions.size() > caps_.max_transactions - tx_count)
        throw std::runtime_error("delta transaction budget exceeded");
      tx_count += b.transactions.size();
    }
    std::set<BlockId> known, included;
    std::map<BlockId, std::string> states;
    for (const auto& tip : current_.anchor.tips) {
      known.insert(tip.id);
      states.emplace(tip.id, tip.state_root);
    }
    for (const auto& blk : step.newly_included) {
      require_id(blk.id);
      if (!hex64(blk.old_state_hash) || !hex64(blk.post_state_hash))
        throw std::runtime_error("missing full state-update hashes");
      if (!included.insert(blk.id).second || known.count(blk.id) || blk.prev.empty() || blk.prev.size() > 2)
        throw std::runtime_error("duplicate or missing new block ancestry");
      states.emplace(blk.id, blk.post_state_hash);
    }
    if (!included.count(step.next.mc) || step.newly_included.size() < 1)
      throw std::runtime_error("MC block missing from diff");
    // Topological sort by full predecessor IDs; split siblings may share a parent.
    std::map<BlockId, const NewBlock*> pending;
    for (const auto& b : step.newly_included) pending.emplace(b.id, &b);
    Counts next_counts = current_.counts;
    auto last = last_;
    while (!pending.empty()) {
      bool advanced = false;
      for (auto it = pending.begin(); it != pending.end();) {
        const auto& b = *it->second;
        if (!std::all_of(b.prev.begin(), b.prev.end(), [&](const auto& p) { return known.count(p) != 0; })) {
          ++it;
          continue;
        }
        std::set<BlockId> distinct(b.prev.begin(), b.prev.end());
        if (distinct.size() != b.prev.size() || (b.id.workchain == -1 &&
            (b.prev.size() != 1 || b.prev.front() != current_.anchor.mc)))
          throw std::runtime_error("invalid predecessor set");
        for (const auto& p : b.prev)
          if (p.workchain != b.id.workchain || p.seqno >= b.id.seqno)
            throw std::runtime_error("invalid shard/MC predecessor");
        if (b.prev.size() != 1 || b.prev.front().shard != b.id.shard)
          throw std::runtime_error("split/merge state transform pending proof");
        if (b.old_state_hash != states.at(b.prev.front()))
          throw std::runtime_error("raw old-state hash differs from predecessor post-state");
        // Tx dictionary is keyed by LT per account; never order different
        // accounts by LT as if that were a global chain.
        std::vector<const Tx*> txs;
        txs.reserve(b.transactions.size());
        for (const auto& tx : b.transactions) txs.push_back(&tx);
        std::sort(txs.begin(), txs.end(), [](const Tx* a, const Tx* z) {
          return std::tie(a->account, a->lt) < std::tie(z->account, z->lt);
        });
        for (const auto* ptr : txs) {
          const auto& tx = *ptr;
          if (tx.account.workchain != b.id.workchain || !hex64(tx.account.address) ||
              !hex64(tx.hash) || !hex64(tx.prev_hash) ||
              !hex64(tx.old_state_hash) || !hex64(tx.new_state_hash))
            throw std::runtime_error("invalid transaction identity");
          auto prior = last.find(tx.account);
          AccountWitness witness{};
          if (prior == last.end()) {
            auto original = step.baseline_witnesses.find(tx.account);
            if (original == step.baseline_witnesses.end())
              throw std::runtime_error("baseline account witness missing");
            witness = original->second;
          } else {
            witness = prior->second;
          }
          if (!hex64(witness.last_hash) || !hex64(witness.state_hash) ||
              tx.lt <= witness.last_lt || tx.prev_lt != witness.last_lt ||
              tx.prev_hash != witness.last_hash || tx.old_state_hash != witness.state_hash ||
              tx.before != witness.status)
            throw std::runtime_error("discontinuous account tx/status/state hash");
          transition(next_counts, tx.before, tx.after);
          if (prior == last.end() && last.size() == caps_.max_tracked_accounts)
            throw std::runtime_error("tracked account budget exceeded");
          last[tx.account] = {tx.after, tx.lt, tx.hash, tx.new_state_hash};
        }
        known.insert(b.id);
        it = pending.erase(it);
        advanced = true;
      }
      if (!advanced) throw std::runtime_error("missing raw block / cyclic ancestry");
    }
    // Verify the resulting frontier, including unchanged old tips; a repeating
    // MC shard tip is not a new event. Split/merge consume parents once, not tx twice.
    std::set<BlockId> frontier = known;
    for (const auto& b : step.newly_included)
      for (const auto& p : b.prev) frontier.erase(p);
    std::set<BlockId> expected;
    for (const auto& t : step.next.tips) expected.insert(t.id);
    if (frontier != expected) throw std::runtime_error("incomplete shard frontier");
    for (const auto& t : step.next.tips)
      if (states.at(t.id) != t.state_root)
        throw std::runtime_error("next tip root differs from raw block post-state");
    Snapshot result;
    result.anchor = step.next;
    result.counts = next_counts;
    result.readiness = Readiness::complete;
    result.reason.clear();
    current_ = std::move(result);
    last_ = std::move(last);
  }

 private:
  Snapshot current_;
  Caps caps_;
  std::map<AccountKey, AccountWitness> last_; // bounded; last tx and state hash included
};

} // namespace tonstat::accounts
