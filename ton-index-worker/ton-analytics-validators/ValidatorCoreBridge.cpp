#include "ValidatorCoreBridge.h"

#include <algorithm>
#include <string>
#include <utility>

namespace tonstat::validators {
namespace {
namespace stage = analytics::validators::stage;
using tonstat::core::AnchorEvidence;

bool full_mc(const ton::BlockIdExt& id) {
  return id.is_masterchain() && id.is_valid_full() && id.id.shard == ton::shardIdAll;
}

bool has_check(const AnchorEvidence& e, const char* code, const std::string& subject,
               const std::string& observed) {
  return std::any_of(e.checks.begin(), e.checks.end(), [&](const tonstat::core::Check& check) {
    return check.code == code && check.subject == subject && check.observed == observed;
  });
}

std::string source_reason(const AnchorEvidence& e, const std::string& fallback) {
  if (e.issues.empty()) return fallback;
  // Keep a bounded diagnostic in the JSON and avoid reflecting unbounded
  // archive-supplied strings into batch records.
  return "core_" + e.issues.front().code.substr(0, 80) + ":" +
         e.issues.front().detail.substr(0, 160);
}

void unresolved(stage::Input& in, stage::Status status, const std::string& reason) {
  const stage::Check check{status, reason, in.expected_mc_id, in.expected_post_state_root};
  in.anchor = {check, check, check};
}

stage::Input map_core(const AnchorEvidence& e, const ton::BlockIdExt& expected,
                      const tonstat::core::NetworkPin& pin,
                      const std::vector<td::Bits256>& allowed_codes) {
  stage::Input in;
  in.expected_mc_id = expected; // never replace the externally selected ID with e.mc.id
  in.expected_post_state_root = e.mc.state_root;
  in.network_zerostate = pin.zerostate.root_hash.to_hex();
  in.network_zerostate_file_hash = pin.zerostate.file_hash.to_hex();
  // The decoder independently requires BOTH its hard-pinned Elector code hash
  // and an explicit caller allowlist. Never extend that pin here.
  in.supported_elector_code_hashes = allowed_codes;
  unresolved(in, stage::Status::pending, source_reason(e, "core_auxiliary_mc_not_verified"));

  if (e.status != tonstat::core::Status::verified_local_archive) {
    unresolved(in, e.status == tonstat::core::Status::error ? stage::Status::invalid
                                                          : stage::Status::pending,
               source_reason(e, e.status == tonstat::core::Status::error
                                    ? "core_auxiliary_mc_error" : "core_auxiliary_mc_incomplete"));
    return in;
  }

  const auto trusted = tonstat::core::testing::trusted_mc0(e.mc.global_id);
  if (e.scope != tonstat::core::Scope::auxiliary_mc_only ||
      !e.snapshot_integrity_checked || !e.issues.empty() || !full_mc(expected) ||
      expected.id.seqno == 0 || e.mc.id != expected ||
      e.mc.state_root == td::Bits256{} || e.mc.state_root != e.mc.state_update_new ||
      !trusted || pin.zerostate != *trusted || e.pin.zerostate != pin.zerostate ||
      !e.mc_state_zerostate || *e.mc_state_zerostate != pin.zerostate ||
      e.network != (e.mc.global_id == -239 ? "mainnet" : "testnet")) {
    unresolved(in, stage::Status::invalid, "core_auxiliary_mc_identity_scope_or_pin_mismatch");
    return in;
  }

  // These are separate local checks, not an adjacent previous-state proof.
  // The native core verifier performs all of them on the ORIGINAL BoC and
  // post-state before recording these check codes. The testing seam below is
  // only a pure mapping test and cannot attest that those reads took place.
  const auto subject = expected.to_str();
  if (!has_check(e, "full_id_handle_block_data_and_original_boc_sha256", subject,
                 expected.file_hash.to_hex()) ||
      !has_check(e, "raw_block_root_and_header", subject, expected.root_hash.to_hex()) ||
      !has_check(e, "merkle_update_new_equals_typed_post_state", subject,
                 e.mc.state_root.to_hex()) ||
      !has_check(e, "external_pin_and_mc_state_mc0_match_trusted_network", subject,
                 pin.zerostate.to_str()) ||
      !has_check(e, "network_from_raw_mc_global_id", subject, e.network) ||
      e.mc_predecessors.size() != 1 || !full_mc(e.mc_predecessors.front()) ||
      e.mc_predecessors.front().id.seqno + 1 != expected.id.seqno ||
      !has_check(e, "raw_mc_header_full_predecessor", subject,
                 e.mc_predecessors.front().to_str())) {
    unresolved(in, stage::Status::invalid, "core_auxiliary_mc_required_local_checks_missing");
    return in;
  }

  const stage::Check ready{stage::Status::ready, "", expected, e.mc.state_root};
  in.anchor = {ready, ready, ready};
  // Intentionally no ElectionBoundary: a named header predecessor is NOT an
  // independently loaded previous state/#36 or first post-election proof.
  return in;
}

}  // namespace

CoreStageOutcome run_verified_mc(const schema::MasterchainBlockDataState& loaded,
                                 const ton::BlockIdExt& expected_full_id,
                                 const tonstat::core::NetworkPin& pin,
                                 const std::vector<td::Bits256>& allowed_codes) {
  if (loaded.shard_blocks_.empty()) {
    stage::Input in;
    in.expected_mc_id = expected_full_id;
    in.network_zerostate = pin.zerostate.root_hash.to_hex();
    in.network_zerostate_file_hash = pin.zerostate.file_hash.to_hex();
    unresolved(in, stage::Status::pending, "missing_mc_entry_for_native_verification");
    return {stage::run(loaded, in), nullptr};
  }
  auto evidence = tonstat::core::verify_auxiliary_mc(loaded.shard_blocks_.front(),
                                                     expected_full_id, pin);
  // map_core is pure but ONLY this production route creates its evidence.
  const auto input = map_core(*evidence, expected_full_id, pin, allowed_codes);
  auto output = stage::run(loaded, input); // no borrowed refs escape this call
  if (input.anchor.raw_block_file_hash.status != stage::Status::ready) {
    // Keep the verifier's actual source reason on every unresolved metric;
    // stage::run correctly refuses extraction but uses generic gate reasons.
    for (auto* metric : {&output.count, &output.frozen_remaining, &output.selected_initial,
                         &output.accepted, &output.settlement, &output.apr, &output.apy}) {
      metric->reason = input.anchor.raw_block_file_hash.reason;
    }
    return {std::move(output), std::move(evidence)};
  }
  // A single auxiliary MC post-state cannot establish a historical election
  // boundary or certify a full day/settlement. Only #34 and matched frozen
  // remaining may be emitted ready on this route.
  output.selected_initial = {};
  output.selected_initial.reason = "first_post_election_config_36_not_proven";
  output.accepted = {};
  output.accepted.reason = "final_election_boundary_not_proven";
  return {std::move(output), std::move(evidence)};
}

namespace testing {
stage::Input map_synthetic_core(const AnchorEvidence& evidence,
                                const ton::BlockIdExt& expected_full_id,
                                const tonstat::core::NetworkPin& pin,
                                const std::vector<td::Bits256>& allowed_codes) {
  return map_core(evidence, expected_full_id, pin, allowed_codes);
}
}  // namespace testing

}  // namespace tonstat::validators
