#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

namespace ton_analytics::wallets {

// This is a pure-STL, in-memory reference reducer, NOT a publication certificate.
// The adapter must prove the attestations below against canonical NodeDB blocks.
struct Scope {
  std::string network;
  // Both identify the network; the stage adapter validates canonical 64-hex encoding.
  std::string zerostate_root_hash;
  std::string zerostate_file_hash;
  std::string calc_version;
  std::string registry_sha256;
  std::set<std::int32_t> workchains;  // shard tips expected on every MC anchor
  bool operator==(const Scope&) const = default;
};

struct BlockId {
  std::int32_t workchain = 0;
  std::uint64_t shard = 0;
  std::uint32_t seqno = 0;
  std::string root_hash;
  std::string file_hash;
  auto operator<=>(const BlockId&) const = default;
};

struct Tip {
  BlockId id;
  std::int64_t gen_utime = 0;
  bool operator==(const Tip&) const = default;
};

struct CoveredBlock {
  BlockId id;
  std::vector<BlockId> predecessors;  // 1 normally; 2 on merge; split shares a predecessor
  std::int64_t gen_utime = 0;
  bool transactions_complete = false;
  bool activation_inputs_complete = false;
  bool activity_inputs_complete = false;
  bool operator==(const CoveredBlock&) const = default;
};

enum class AccountStatus { nonexist, uninit, active, frozen };
enum class EvidenceKind { unknown, qualified, excluded };

struct CodeEvidence {
  EvidenceKind kind = EvidenceKind::unknown;
  std::string code_hash;
  std::string wallet_type_id;  // stable registry type only for qualified
  std::string source;          // verified state/StateInit/pre-state/replay provenance
  bool operator==(const CodeEvidence&) const = default;
};

struct WalletObservation {
  std::string account;  // canonical workchain:256-bit address (adapter validates syntax)
  std::uint64_t lt = 0;
  std::string tx_hash;
  std::int64_t now = 0;  // tx.now, NOT message.created_at or processing time
  BlockId block;        // emitting MC or first-included shard block, full ID
  AccountStatus orig = AccountStatus::nonexist;
  AccountStatus end = AccountStatus::nonexist;
  CodeEvidence activation_code;  // code at FIRST activation, not execution/post-current by guess
  CodeEvidence execution_code;   // code running at this tx, before any SETCODE
  bool actual_qualifying_outgoing = false; // emitted out msg, source==account, !bounced
  std::string outgoing_message_hash;       // actual message identity if true
  bool operator==(const WalletObservation&) const = default;
};

struct BlockEnvelope {
  Scope scope;
  BlockId mc;
  BlockId prev_mc;  // full canonical predecessor, not just seqno
  std::int64_t mc_utime = 0;
  std::vector<CoveredBlock> new_shard_blocks; // complete independent tip graph diff
  std::vector<Tip> current_shard_tips;        // ALL workchains/branches, even unchanged
  bool graph_diff_verified = false;          // independently compared to tip predecessors
  bool time_rules_verified = false;          // tx.now==block time, descendant monotonicity
  std::string graph_diff_attestation;        // independent graph-vs-tips verifier result
  std::string time_rules_attestation;        // independent block-time-rule verifier result
  std::string tx_inventory_attestation;      // independent source tx/message inventory result
  bool mc_transactions_complete = false;
  bool mc_activation_inputs_complete = false;
  bool mc_activity_inputs_complete = false;
  std::vector<WalletObservation> observations; // includes non-wallet/excluded active txs
  std::uint64_t revision = 0;                   // coordinator-assigned; not arrival order
  bool operator==(const BlockEnvelope&) const = default;
};

enum class BaselineKind { genesis, verified_historical_bootstrap };
struct LifetimeBaseline {
  Scope scope;
  BaselineKind kind = BaselineKind::genesis;
  BlockId mc;                 // genesis MC zero or independently checked CH anchor
  std::int64_t mc_utime = 0;
  std::vector<Tip> shard_tips;
  bool canonical_anchor_verified = false;
  bool full_history_verified = false;       // all prior active transitions, not wallet-only
  bool all_initial_accounts_verified = false;
  bool shard_frontier_verified = false;
  std::string attestation_id;              // explicit source proof, NOT inferred from 2 MCs
  std::set<std::string> genesis_active_accounts; // ONLY zerostate, never checkpoint active set
  std::vector<WalletObservation> first_active_history; // CH bootstrap: ALL prior first active
  bool operator==(const LifetimeBaseline&) const = default;
};

// A separately certified event-only left frontier. Its proof IDs must refer to
// independent canonical MC, all-tip, and time/transaction coverage checks;
// a pair of locally scanned blocks is NOT a checkpoint. It confers no knowledge
// of addresses active before this anchor and never enables activation counts.
struct EventRangeCheckpoint {
  Scope scope;
  BlockId mc;
  std::int64_t mc_utime = 0;
  std::vector<Tip> shard_tips;
  bool canonical_anchor_verified = false;
  bool independent_frontier_verified = false;
  bool complete_event_left_boundary_verified = false;
  std::string canonical_anchor_attestation;
  std::string independent_frontier_attestation;
  std::string event_left_boundary_attestation;
  bool operator==(const EventRangeCheckpoint&) const = default;
};

struct FirstActiveFact {
  bool genesis_state = false;
  WalletObservation witness; // if genesis_state, only account is populated
  bool operator==(const FirstActiveFact&) const = default;
};

struct DayMetrics {
  std::int64_t utc_day_start = 0;
  // nullopt means pending/unknown, NEVER zero. Each metric closes independently.
  std::optional<std::uint64_t> daily_activations;
  std::optional<std::uint64_t> cumulative_activations;
  std::optional<std::uint64_t> dau;
  std::optional<std::uint64_t> mau_30d;
  std::map<std::string, std::uint64_t> activation_types;
  std::uint64_t generation = 0; // changes on correction; a query is NOT a publication
};

class WalletMetrics {
 public:
  explicit WalletMetrics(Scope scope, std::size_t max_envelopes = 10000,
                         std::size_t max_observations = 100000);
  // Pilot mode (without baseline) may ingest blocks but cannot certify lifetime.
  // A CH baseline is permitted only with explicitly attested full historical first-
  // active facts, including non-wallet/excluded and genesis-active accounts.
  void set_baseline(LifetimeBaseline baseline);
  // Independent DAU/MAU coverage; NEVER a lifetime or first-active certificate.
  void set_event_checkpoint(EventRangeCheckpoint checkpoint);
  void put(BlockEnvelope envelope); // same revision/content idempotent; conflicts throw
  DayMetrics day(std::int64_t utc_day_start) const;
  std::optional<FirstActiveFact> first_active(const std::string& account) const;
  std::optional<BlockId> contiguous_watermark() const; // lifetime if present, otherwise event
  std::optional<BlockId> event_watermark() const;
  std::uint64_t generation() const { return generation_; }

 private:
  struct State;
  State calculate(bool lifetime) const;
  Scope scope_;
  std::size_t max_envelopes_;
  std::size_t max_observations_;
  std::optional<LifetimeBaseline> baseline_;
  std::optional<EventRangeCheckpoint> event_checkpoint_;
  std::map<std::uint32_t, BlockEnvelope> envelopes_;
  std::uint64_t generation_ = 0;
};

} // namespace ton_analytics::wallets
