#pragma once

#include "WalletEventExtractor.h"
#include "WalletMetrics.h"

#include <cstddef>
#include <optional>
#include <string>
#include <vector>

namespace ton_analytics::wallets::stage {

// NOT an attestation generator. The caller must independently check the canonical
// MC0/root+file network identity, MC/previous full IDs, all current tips, every
// first-included predecessor (including split/merge), block times, AND complete
// raw tx/HASH_UPDATE/out-msg inventories against canonical NodeDB blocks.
// In particular these fields must not be populated from events::Batch or its counters.
// The stage only cross-checks the supplied independent evidence and fails closed.
struct RawTransaction {
  std::string account; // raw wc:64-hex; the sending tx account, not msg destination
  std::uint64_t lt = 0;
  std::string hash_hex;
  // Both endpoints from this tx's native HASH_UPDATE, independently read by
  // the caller. Never infer old_hash from a previous observation or post-code.
  std::string pre_state_hash_hex;
  std::string post_state_hash_hex;
  std::uint32_t now = 0;
  AccountStatus orig = AccountStatus::nonexist;
  AccountStatus end = AccountStatus::nonexist;
  // First *actual* qualifying emitted out message in tx order, if present.
  // Caller verifies source == account, internal !bounced OR external-out, and hash.
  std::optional<std::string> first_qualifying_message_hash_hex;
};

struct BlockInventory {
  BlockId id; // MC or one first-included shard block (never an unchanged tip)
  std::int64_t gen_utime = 0;
  bool transactions_complete = false;
  bool statuses_complete = false;
  bool outgoing_complete = false;
  std::vector<RawTransaction> transactions; // includes ordinary non-wallet txs
};

struct VerifiedEnvelope {
  Scope scope;
  // Independent canonical MC0 ID. Its root/file hashes must both match scope;
  // this anchor is NOT a lifetime baseline or a certificate of historical coverage.
  BlockId zerostate_mc;
  bool zerostate_anchor_verified = false;
  std::string zerostate_anchor_attestation;
  BlockId mc;
  BlockId prev_mc;
  std::int64_t mc_utime = 0;
  std::vector<CoveredBlock> first_included_shards; // independent graph; flags ignored
  std::vector<Tip> current_shard_tips; // all workchains, including unchanged tips
  std::vector<BlockInventory> raw_blocks; // exactly MC + first_included_shards
  bool graph_diff_verified = false;
  bool time_rules_verified = false;
  bool raw_inventory_verified = false;
  std::string graph_diff_attestation;
  std::string time_rules_attestation;
  std::string raw_inventory_attestation;
  std::uint64_t revision = 0; // assigned by external coordinator, not this stage
};

struct Limits {
  std::size_t max_blocks = 1024;
  std::size_t max_tips = 1024;
  std::size_t max_transactions = 100000;
};

// Returns a reducer input ONLY. No baseline, checkpoint, lifetime firstness,
// publication, day closure, or writer commit is certified or exposed here.
// Throws std::invalid_argument on incomplete, duplicate, inconsistent or
// ambiguous evidence; std::length_error on configured memory limits.
BlockEnvelope build(const VerifiedEnvelope& verified, const events::Batch& batch,
                    Limits limits = {});

} // namespace ton_analytics::wallets::stage
