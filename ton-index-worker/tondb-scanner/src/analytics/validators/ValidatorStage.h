#pragma once

#include "ValidatorElectionObservation.h"
#include "ValidatorSnapshot.h"

#include <optional>
#include <string>
#include <vector>

namespace analytics::validators::stage {

inline constexpr const char *kStageVersion = "validator-stage-producer-v2";

enum class Status { ready, pending, invalid };

// These are attestations from a future audited, trusted reader, NOT proofs made
// by this stage. Each must refer to the exact full block ID and post-state root.
// A caller-supplied boolean, or equality of hashes alone, is insufficient.
struct Check {
  Status status{Status::pending};
  std::string reason{"not_verified"};
  ton::BlockIdExt mc_id;
  td::Bits256 post_state_root;
};

struct AnchorEvidence {
  Check raw_block_file_hash;  // raw BoC file hash checked against full MC ID
  Check header_and_predecessor;  // full header/MC predecessor checked
  Check state_update;  // block state_update binds this post-state root
};

struct ElectionBoundary {
  // Reader verified this is the FIRST post-election #36 for this election,
  // not just a later MC state with an unchanged #36. Prior MC identity and
  // #36 must have been inspected independently, not inferred from timestamps.
  Check first_post_election;
  Check previous_state_and_config36;  // verified previous state + previous #36
  ton::BlockIdExt previous_mc_id;
  td::Bits256 previous_post_state_root;
  std::optional<td::Bits256> previous_config36_hash;  // null = proved absent
  uint32_t election_id{};
  td::Bits256 selected_vset_hash;
};

struct Input {
  std::string network_zerostate;  // nonzero 64-hex zerostate ROOT hash
  std::string network_zerostate_file_hash;  // nonzero 64-hex zerostate FILE hash
  ton::BlockIdExt expected_mc_id;
  td::Bits256 expected_post_state_root;
  AnchorEvidence anchor;
  std::optional<ElectionBoundary> election_boundary;
  std::vector<td::Bits256> supported_elector_code_hashes;
};

// Pure owned facts; no Cell, CellSlice, reader, account handle, or borrowed
// reference survives the synchronous extraction call.
struct ValidatorFact {
  td::Bits256 pubkey;
  std::optional<td::Bits256> raw_holder;
  std::optional<td::Bits256> adnl;
  std::optional<uint16_t> roster_index;
  std::optional<uint64_t> weight;
  std::optional<std::string> stake_nanoton;
  std::optional<bool> banned;
};

struct Metric {
  Status status{Status::pending};
  std::string reason{"not_evaluated"};
  std::optional<std::string> value;  // count integer or stake nanoTON; never zero by default
  std::optional<td::Bits256> vset_hash;
  std::optional<td::Bits256> source_root_hash;  // #34, frozen dict, past dict, cur_elect
  std::optional<td::Bits256> elector_account_hash, elector_code_hash;
  std::optional<uint32_t> election_id;
  std::vector<ValidatorFact> validators;
};

struct Output {
  std::string calc_version{kStageVersion};
  std::string scope{"single_attested_mc_post_state/producer_only"};
  std::string snapshot_decoder_version{kDecoderVersion};
  std::string network_zerostate;
  std::string network_zerostate_file_hash;
  ton::BlockIdExt mc_id;
  td::Bits256 post_state_root;
  uint32_t gen_utime{};
  AnchorEvidence anchor;
  std::optional<ElectionBoundary> election_boundary;
  bool producer_only{true};
  bool writer_committed{false};
  bool publication{false};
  Metric count;               // config #34, independent of the other metrics
  Metric selected_initial;    // only at first post-election #36 + exact past election
  Metric accepted;            // final cur_elect, exact election/vset membership
  Metric frozen_remaining;    // current #34, not selected_initial
  Metric settlement;          // requires selection->pre continuity and isolated post tx
  Metric apr;
  Metric apy;
};

// No DB access, no writer, no background work; loaded and its reader must stay
// alive for the duration of this call. Missing evidence yields pending, never 0.
Output run(const schema::MasterchainBlockDataState &loaded, const Input &input);

namespace testing {
// Synthetic projection seam: NOT an alternative verified reader/API. It still
// checks supplied IDs/evidence but cannot authenticate their origin. Never use
// its results as proof that an actual historical MC state was read.
Output project_synthetic(const Input &input, const Snapshot &snapshot,
                         const election::Observation &observation);
}  // namespace testing

}  // namespace analytics::validators::stage
