#pragma once

#include <algorithm>
#include <cstddef>
#include <optional>
#include <string>
#include <vector>

namespace assets_analytics {

// Wallet verification, NOT account lookup. found means audited jetton evidence;
// an account with a successful getter but no context audit remains unknown.
enum class Status { found, not_present, unknown, error };
enum class AccountLookup { found, not_present, unknown, error };
enum class Binding { untested, matched, unmatched };

struct TipSource {
  std::string block_id;          // full BlockIdExt including root and file hashes
  std::string state_root_hash;   // state root, NOT the block root hash
  bool operator==(const TipSource& other) const {
    return block_id == other.block_id && state_root_hash == other.state_root_hash;
  }
};

// Deterministic length-prefixed encoding; canonical irrespective of input order.
// Digest with SHA-256 before recording. Entries contain identifiers/hashes only.
inline std::string canonical_tip_manifest(std::vector<TipSource> tips) {
  std::sort(tips.begin(), tips.end(), [](const TipSource& a, const TipSource& b) {
    return a.block_id < b.block_id || (a.block_id == b.block_id && a.state_root_hash < b.state_root_hash);
  });
  std::string out = std::to_string(tips.size()) + ":";
  for (const auto& tip : tips) {
    out += std::to_string(tip.block_id.size()) + ":" + tip.block_id;
    out += std::to_string(tip.state_root_hash.size()) + ":" + tip.state_root_hash;
  }
  return out;
}

struct Provenance {
  std::string network;
  std::string zerostate;
  std::string mc_block_id;
  std::string mc_state_root_hash;
  std::vector<TipSource> current_shard_tips;  // COMPLETE supplied manifest, even unrelated tips
  std::string tip_manifest_sha256;            // canonical ordered block ID + state-root entries
  std::string tip_block_id;
  std::string tip_state_root_hash;
  std::string master_tip_block_id;
  std::string master_tip_state_root_hash;
  std::string config_hash;
  unsigned historical_now{0};
  // Caller attestations, NOT independently verified on-chain proofs: we only check
  // supplied loaded root hashes and shard identities locally. The caller must prove
  // state updates, manifest completeness and config↔MC binding before publication.
  bool caller_attests_state_updates{false};
  bool caller_attests_manifest_complete{false};
  bool caller_attests_config_from_mc{false};
  // Native Args has zero block/trans LT, zero seed, absent prev-blocks info.
  std::string vm_context_limits{"native_c7_lt_zero_seed_zero_prev_blocks_absent"};
};

struct AccountEvidence {
  AccountLookup lookup{AccountLookup::unknown}; // address exists in its proven shard root
  std::string address;
  std::string state_hash;
  std::string code_hash;
  std::string data_hash;
  std::string account_status;
  std::string ton_balance_nanoton;
  std::string extra_currencies_hash;
};

// External, versioned audit of both getter methods/code and their dependencies on
// unavailable C7 fields. This is NOT an on-chain proof and is never manufactured
// by the extractor. Verifier must independently authenticate report_id/digest and
// confirm the allowlist's method/code/context analysis before supplying this record.
struct GetterContextAudit {
  std::string report_id;
  std::string report_sha256;
  std::string allowlist_policy_version;
  std::string c7_dependency_assessment;
  std::string wallet_address;
  std::string wallet_state_hash;
  std::string wallet_code_hash;
  std::string master_address;
  std::string master_state_hash;
  std::string master_code_hash;
  std::string mc_block_id;
  std::string mc_state_root_hash;
  std::string tip_manifest_sha256;
  std::vector<TipSource> current_shard_tips;
  std::string config_hash;
  unsigned historical_now{0};
  std::string wallet_method;
  std::string master_method;
  std::string audited_vm_context_limits;
};

struct Observation {
  Status status{Status::unknown};  // verified wallet identity/balance; distinct from wallet.lookup
  Binding binding{Binding::untested}; // raw getter comparison, NOT proof of C7 independence
  std::string reason;
  Provenance source;
  AccountEvidence wallet;
  AccountEvidence master;
  std::optional<std::string> raw_signed_balance;
  std::optional<std::string> owner;
  std::optional<std::string> master_address;
  std::optional<std::string> getter_wallet_code_hash;
  std::optional<std::string> master_returned_wallet;
  std::optional<GetterContextAudit> context_audit;
  // A bounded address sample is never a global count or daily certificate.
  static constexpr bool is_global_snapshot_complete = false;
};

// Account for caller-supplied audit bytes, one materialized shared manifest,
// and up to two copies per observation (source + attached audit). Divisions
// rather than multiplication keep the check safe at SIZE_MAX.
inline bool fits_aggregate_provenance_budget(size_t audit_bytes, size_t manifest_bytes,
                                             size_t observations, size_t cap) {
  if (audit_bytes > cap || !manifest_bytes) return false;
  size_t remaining = cap - audit_bytes;
  if (manifest_bytes > remaining) return false;
  remaining -= manifest_bytes;
  return observations <= remaining / manifest_bytes / 2;
}

inline bool valid_report_digest(const std::string& digest) {
  return digest.size() == 64 && std::all_of(digest.begin(), digest.end(), [](char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
  });
}

inline bool matching_context_audit(const Observation& o) {
  if (!o.context_audit) return false;
  const auto& a = *o.context_audit;
  return !a.report_id.empty() && valid_report_digest(a.report_sha256) &&
         !a.allowlist_policy_version.empty() &&
         a.c7_dependency_assessment == "audited_independent_of_unavailable_c7_fields" &&
         a.wallet_method == "get_wallet_data" && a.master_method == "get_wallet_address" &&
         a.wallet_address == o.wallet.address && a.wallet_state_hash == o.wallet.state_hash &&
         a.wallet_code_hash == o.wallet.code_hash && a.master_address == o.master.address &&
         a.master_state_hash == o.master.state_hash && a.master_code_hash == o.master.code_hash &&
         a.mc_block_id == o.source.mc_block_id && a.mc_state_root_hash == o.source.mc_state_root_hash &&
         a.tip_manifest_sha256 == o.source.tip_manifest_sha256 &&
         a.current_shard_tips == o.source.current_shard_tips &&
         a.config_hash == o.source.config_hash && a.historical_now == o.source.historical_now &&
         a.audited_vm_context_limits == o.source.vm_context_limits;
}

inline Status classify(const Observation& o) {
  const auto& p = o.source;
  const auto tip_present = [&](const std::string& block_id, const std::string& root) {
    return (block_id == p.mc_block_id && root == p.mc_state_root_hash) ||
           std::find(p.current_shard_tips.begin(), p.current_shard_tips.end(), TipSource{block_id, root}) !=
               p.current_shard_tips.end();
  };
  if (o.wallet.lookup == AccountLookup::error || o.master.lookup == AccountLookup::error) return Status::error;
  const bool source_ready = p.caller_attests_state_updates && p.caller_attests_manifest_complete &&
                            p.caller_attests_config_from_mc && !p.network.empty() &&
                            !p.zerostate.empty() && !p.mc_block_id.empty() &&
                            !p.mc_state_root_hash.empty() && !p.tip_manifest_sha256.empty() &&
                            !p.current_shard_tips.empty() && !p.tip_block_id.empty() &&
                            !p.tip_state_root_hash.empty() && !p.config_hash.empty() &&
                            p.historical_now != 0 && tip_present(p.tip_block_id, p.tip_state_root_hash);
  if (!source_ready) return Status::unknown;
  // Lookup proves absence only in a selected, rooted shard; no getter audit needed.
  if (o.wallet.lookup == AccountLookup::not_present) return Status::not_present;
  if (o.wallet.lookup != AccountLookup::found || o.master.lookup != AccountLookup::found ||
      o.wallet.account_status != "active" || o.master.account_status != "active" ||
      o.wallet.state_hash.empty() || o.wallet.code_hash.empty() || o.wallet.data_hash.empty() ||
      o.master.state_hash.empty() || o.master.code_hash.empty() || o.master.data_hash.empty() ||
      p.master_tip_block_id.empty() || p.master_tip_state_root_hash.empty() ||
      !tip_present(p.master_tip_block_id, p.master_tip_state_root_hash) ||
       !o.raw_signed_balance || !o.owner || o.owner->empty() ||
       !o.master_address || o.master_address->empty() || *o.master_address != o.master.address ||
       !o.getter_wallet_code_hash || o.getter_wallet_code_hash->empty() ||
       !o.master_returned_wallet || o.master_returned_wallet->empty() || o.binding != Binding::matched ||
      *o.master_returned_wallet != o.wallet.address || o.raw_signed_balance->empty() ||
      !std::all_of(o.raw_signed_balance->begin(), o.raw_signed_balance->end(),
                   [](char c) { return c >= '0' && c <= '9'; }) ||
      !matching_context_audit(o)) return Status::unknown;
  return Status::found;
}

}  // namespace assets_analytics
