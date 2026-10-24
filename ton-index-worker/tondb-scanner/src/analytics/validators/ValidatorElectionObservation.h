#pragma once

// IndexData.h currently depends on this declaration without including it.
#include "td/utils/base64.h"
#include "IndexData.h"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace analytics::validators::election {

// Never interpreted as an APR, a transfer, or a withdrawn amount.
enum class Status { ready, pending, invalid };
struct Evidence {
  Status status{Status::pending};
  std::string reason{"not_evaluated"};
};

struct Candidate {
  td::Bits256 pubkey, raw_holder, adnl;
  std::string stake_nanoton;
  uint32_t stake_at{}, max_factor{};
};
struct Elected {
  uint16_t index{}; // original Hashmap 16 key, NOT native iteration position
  td::Bits256 pubkey;
  uint64_t weight{};
  std::optional<td::Bits256> adnl;
};
struct Frozen {
  td::Bits256 pubkey, raw_holder;
  uint64_t weight{};
  std::string stake_nanoton;
  bool banned{};
};
struct Credit {
  td::Bits256 raw_holder;
  std::string amount_nanoton;
};

struct Observation {
  std::string network_zerostate;
  ton::BlockIdExt mc_id;
  td::Bits256 state_hash;
  bool state_update_verified{};
  uint32_t gen_utime{};
  std::optional<td::Bits256> config36_hash, elector_address,
      elector_account_hash, elector_code_hash, elector_data_hash,
      current_root_hash, past_root_hash, credits_root_hash, frozen_root_hash;

  Evidence roster, applications, past, credits;
  uint32_t since{}, until{};
  uint16_t total{}, main{};
  uint64_t total_weight{};
  std::vector<Elected> elected; // only when roster is ready

  std::optional<uint32_t> current_election_id;
  std::optional<bool> current_finished, current_failed;
  std::optional<std::string> accepted_nanoton;
  std::vector<Candidate> candidates; // only when applications are ready

  // past.ready + past_present=false means a COMPLETE dictionary proves this
  // SPECIFIED election ID absent. pending never proves absence. Comparing
  // adjacent observations is NOT proof of an isolated unfreeze transaction:
  // the caller must independently verify transition/tx provenance for yield.
  std::optional<uint32_t> requested_election_id;
  std::optional<td::Bits256> requested_vset_hash;
  std::optional<bool> past_present;
  std::optional<uint32_t> unfreeze_at, stake_held_for;
  std::optional<std::string> frozen_total_nanoton, bonuses_nanoton;
  std::vector<Frozen> frozen; // only when past.ready && past_present

  // Full holder-key dictionary, including unchanged holders; no pubkey or
  // election attribution. Empty AND credits.ready proves zero entries. The
  // caller must compare whole before/after maps, including unexpected holders.
  std::optional<std::string> credits_total_nanoton;
  std::vector<Credit> holder_credits; // only when credits.ready
};

struct Input {
  std::string network_zerostate; // nonzero 64-digit zerostate ROOT hex
  ton::BlockIdExt expected_mc_id;
  td::Bits256 expected_state_hash;
  bool state_update_verified{false}; // independently established by reader
  std::vector<td::Bits256> supported_elector_code_hashes;
  // For later pre/post states supply BOTH. If omitted, selection resolves the
  // unique past election by the config #36 cell hash, never by timestamps.
  std::optional<uint32_t> election_id;
  std::optional<td::Bits256> expected_vset_hash;
};

// Pure fail-closed checks for synthetic tests and for the cell decoder.
void verify_elected(Observation &out);
void verify_applications(Observation &out);
void verify_past(Observation &out);
void verify_credits(Observation &out);

// Decode a standalone raw #36 ValidatorSet cell. This does NOT authenticate
// the cell against an MC state; observe_election does that separately. Throws
// on malformed cells and cross-check failures. Kept public for cell fixtures.
void decode_elected_roster_cell(Observation &out, td::Ref<vm::Cell> cell);

// Synchronous only; copies all facts, retains no cell/reader references.
// The caller must attest state_update binding to the full MC block ID; this
// function additionally compares the actual handle, block root and state root.
td::Result<Observation> observe_election(
    const schema::MasterchainBlockDataState &loaded, const Input &input);

} // namespace analytics::validators::election
