#include "ValidatorStage.h"

#include <algorithm>
#include <utility>

namespace analytics::validators::stage {
namespace {

void pending(Metric &m, std::string reason) {
  m = {};
  m.reason = std::move(reason);
}

void invalid(Metric &m, std::string reason) {
  pending(m, std::move(reason));
  m.status = Status::invalid;
}

Status status(Readiness x) {
  if (x == Readiness::ready) return Status::ready;
  return x == Readiness::invalid ? Status::invalid : Status::pending;
}

Status status(election::Status x) {
  if (x == election::Status::ready) return Status::ready;
  return x == election::Status::invalid ? Status::invalid : Status::pending;
}

void from_snapshot(Metric &m, const analytics::validators::Metric &source) {
  m.status = status(source.status);
  m.reason = source.reason;
  if (m.status == Status::ready && source.value) {
    m.value = source.value;
  } else if (m.status == Status::ready) {
    invalid(m, "ready_metric_missing_value");
  }
}

void from_election(Metric &m, const election::Evidence &source) {
  m.status = status(source.status);
  m.reason = source.reason;
}

enum class Gate { verified, missing, invalid };

Gate check(const Check &c, const Input &input) {
  if (c.status == Status::invalid) return Gate::invalid;
  if (c.status != Status::ready) return Gate::missing;
  return c.mc_id == input.expected_mc_id &&
                 c.post_state_root == input.expected_post_state_root
             ? Gate::verified : Gate::invalid;
}

Gate anchor_gate(const Input &input) {
  if (!valid_network_zerostate(input.network_zerostate) ||
      !input.expected_mc_id.is_masterchain() || !input.expected_mc_id.is_valid_full() ||
      input.expected_post_state_root == td::Bits256{})
    return Gate::invalid;
  // The extractors decode with the root only; no stage fact is ready without
  // the complete zerostate root+file network provenance from the adapter.
  if (input.network_zerostate_file_hash.empty()) return Gate::missing;
  if (!valid_network_zerostate(input.network_zerostate_file_hash)) return Gate::invalid;
  const auto file = check(input.anchor.raw_block_file_hash, input);
  const auto header = check(input.anchor.header_and_predecessor, input);
  const auto state = check(input.anchor.state_update, input);
  if (file == Gate::invalid || header == Gate::invalid || state == Gate::invalid)
    return Gate::invalid;
  if (file == Gate::missing || header == Gate::missing || state == Gate::missing)
    return Gate::missing;
  return Gate::verified;
}

template <class T>
bool identity(const T &source, const Input &input) {
  return source.network_zerostate == input.network_zerostate &&
         source.mc_id == input.expected_mc_id &&
         source.state_hash == input.expected_post_state_root &&
         source.state_update_verified;
}

void all_pending(Output &out, const std::string &why, Status s = Status::pending) {
  for (auto *m : {&out.count, &out.selected_initial, &out.accepted,
                  &out.frozen_remaining}) {
    pending(*m, why);
    m->status = s;
  }
  pending(out.settlement, why);
  pending(out.apr, "settlement_not_verified");
  pending(out.apy, "settlement_not_verified");
}

bool boundary_verified(const Input &in, const election::Observation &o) {
  if (!in.election_boundary) return false;
  const auto &b = *in.election_boundary;
  return check(b.first_post_election, in) == Gate::verified &&
         b.previous_state_and_config36.status == Status::ready &&
         b.previous_state_and_config36.mc_id == b.previous_mc_id &&
         b.previous_state_and_config36.post_state_root == b.previous_post_state_root &&
         b.previous_mc_id.is_masterchain() && b.previous_mc_id.is_valid_full() &&
         b.previous_mc_id.seqno() < UINT32_MAX &&
         b.previous_mc_id.seqno() + 1 == in.expected_mc_id.seqno() &&
         b.previous_post_state_root != td::Bits256{} &&
         b.previous_post_state_root != in.expected_post_state_root &&
         (!b.previous_config36_hash || *b.previous_config36_hash != b.selected_vset_hash) &&
         b.election_id != 0 && o.requested_election_id == b.election_id &&
         o.config36_hash == b.selected_vset_hash &&
         o.requested_vset_hash == b.selected_vset_hash;
}

bool reviewed_elector(const std::optional<td::Bits256> &code, const Input &in) {
  return code && elector_code_enabled_for_decoder(*code,
                                                   in.supported_elector_code_hashes);
}

Output project(const Input &input, const Snapshot &source,
               const election::Observation &observed) {
  Output out;
  out.network_zerostate = input.network_zerostate;
  out.network_zerostate_file_hash = input.network_zerostate_file_hash;
  out.mc_id = input.expected_mc_id;
  out.post_state_root = input.expected_post_state_root;
  out.anchor = input.anchor;
  out.election_boundary = input.election_boundary;
  out.settlement.reason = "missing_independent_selection_pre_continuity_adjacent_post_isolated_elector_tx_and_credits_delta";
  out.apr.reason = "settlement_not_verified";
  out.apy.reason = "settlement_not_verified";
  auto gate = anchor_gate(input);
  if (gate != Gate::verified) {
    all_pending(out, gate == Gate::invalid ? "invalid_anchor_evidence" : "unverified_anchor_evidence",
                gate == Gate::invalid ? Status::invalid : Status::pending);
    return out;
  }
  // Neither a ready source status nor a boundary attestation can override a
  // conflicting gen_utime at the same full anchor.
  if (identity(source, input) && identity(observed, input) && source.gen_utime &&
      observed.gen_utime && source.gen_utime != observed.gen_utime) {
    all_pending(out, "extractor_anchor_identity_mismatch", Status::invalid);
    return out;
  }
  out.gen_utime = identity(source, input) ? source.gen_utime : observed.gen_utime;
  out.snapshot_decoder_version = source.decoder_version;

  if (!identity(source, input)) {
    invalid(out.count, "snapshot_anchor_identity_mismatch");
    pending(out.frozen_remaining, "snapshot_anchor_identity_mismatch");
  } else {
    from_snapshot(out.count, source.count);
    if (out.count.status == Status::ready) {
      if (!source.config34_hash) {
        invalid(out.count, "count_missing_config_34_hash");
      } else {
        auto roster = source;
        validate_roster(roster);
        if (roster.count.status != Readiness::ready || roster.count.value != source.count.value) {
          invalid(out.count, "config_34_roster_invariant");
        } else {
          out.count.vset_hash = source.config34_hash;
          out.count.source_root_hash = source.config34_hash;
          for (const auto &member : source.members)
            out.count.validators.push_back({member.pubkey, std::nullopt, member.adnl,
                                            member.index, member.weight, std::nullopt,
                                            std::nullopt});
        }
      }
    }
    pending(out.frozen_remaining, "config_34_count_not_ready");
    if (out.count.status == Status::ready) {
      from_snapshot(out.frozen_remaining, source.frozen_remaining);
      if (out.frozen_remaining.status == Status::ready) {
        if (source.elector_code_hash && !reviewed_elector(source.elector_code_hash, input)) {
          pending(out.frozen_remaining, "elector_code_not_reviewed_and_enabled");
        } else if (!source.frozen_declared_total_nanoton || !source.frozen_root_hash ||
                   !source.elector_account_hash || !source.elector_code_hash) {
          invalid(out.frozen_remaining, "frozen_provenance_or_total_missing");
        } else {
          auto frozen = source;
          validate_frozen(frozen, *source.frozen_declared_total_nanoton);
          if (frozen.frozen_remaining.status != Readiness::ready ||
              frozen.frozen_remaining.value != source.frozen_remaining.value) {
            invalid(out.frozen_remaining, "frozen_roster_or_sum_invariant");
          } else {
            out.frozen_remaining.vset_hash = source.config34_hash;
            out.frozen_remaining.source_root_hash = source.frozen_root_hash;
            out.frozen_remaining.elector_account_hash = source.elector_account_hash;
            out.frozen_remaining.elector_code_hash = source.elector_code_hash;
            out.frozen_remaining.election_id = source.election_id;
            for (const auto &f : source.frozen)
              out.frozen_remaining.validators.push_back({f.pubkey, f.raw_holder, std::nullopt,
                  std::nullopt, f.weight, f.stake_nanoton, f.banned});
          }
        }
      }
    }
  }

  if (!identity(observed, input)) {
    invalid(out.selected_initial, "election_anchor_identity_mismatch");
    invalid(out.accepted, "election_anchor_identity_mismatch");
    return out;  // #34 remains independent of a failed election observation
  }

  // Recheck the independently decoded #36 and past dictionary before emitting
  // any selected/accepted fact; #34 does not gate either metric.
  auto election = observed;
  if (election.roster.status == election::Status::ready)
    election::verify_elected(election);
  if (election.past.status == election::Status::ready && election.past_present.value_or(false))
    election::verify_past(election);

  pending(out.selected_initial, "first_post_election_config_36_not_proven");
  if (input.election_boundary && input.election_boundary->first_post_election.status == Status::invalid)
    invalid(out.selected_initial, "invalid_first_post_election_evidence");
  if (boundary_verified(input, election)) {
    from_election(out.selected_initial, election.past);
    if (out.selected_initial.status == Status::ready) {
      if (election.elector_code_hash && !reviewed_elector(election.elector_code_hash, input)) {
        pending(out.selected_initial, "elector_code_not_reviewed_and_enabled");
      } else if (election.roster.status != election::Status::ready ||
          !election.past_present.value_or(false) || !election.frozen_total_nanoton ||
          !election.past_root_hash || !election.frozen_root_hash ||
          !election.elector_account_hash || !election.elector_code_hash ||
          election.frozen.size() != election.elected.size()) {
        invalid(out.selected_initial, "selected_roster_or_past_incomplete");
      } else if (std::any_of(election.frozen.begin(), election.frozen.end(),
                             [](const election::Frozen &f) { return f.banned; })) {
        // In the pinned Elector version winners are born unbanned. A later
        // fined/banned frozen state is not original selection principal P.
        invalid(out.selected_initial, "selected_winner_banned_in_reviewed_elector");
      } else {
        out.selected_initial.value = election.frozen_total_nanoton;
        out.selected_initial.vset_hash = election.config36_hash;
        out.selected_initial.source_root_hash = election.past_root_hash;
        out.selected_initial.elector_account_hash = election.elector_account_hash;
        out.selected_initial.elector_code_hash = election.elector_code_hash;
        out.selected_initial.election_id = election.requested_election_id;
        for (const auto &f : election.frozen)
          out.selected_initial.validators.push_back({f.pubkey, f.raw_holder, std::nullopt,
              std::nullopt, f.weight, f.stake_nanoton, f.banned});
      }
    }
  }

  pending(out.accepted, "final_cur_elect_same_vset_not_proven");
  if (election.applications.status == election::Status::invalid ||
      election.past.status == election::Status::invalid ||
      election.roster.status == election::Status::invalid) {
    invalid(out.accepted, "election_component_invalid");
  } else if (election.applications.status == election::Status::ready) {
    election::verify_applications(election);
    if (election.applications.status != election::Status::ready) {
      from_election(out.accepted, election.applications);
    } else if (election.elector_code_hash &&
               !reviewed_elector(election.elector_code_hash, input)) {
      pending(out.accepted, "elector_code_not_reviewed_and_enabled");
    } else if (election.config36_hash != election.requested_vset_hash ||
               !election.requested_election_id ||
               election.current_election_id != election.requested_election_id ||
               !election.current_finished.value_or(false) ||
               election.current_failed.value_or(true) || !election.accepted_nanoton ||
               !election.current_root_hash || !election.past_root_hash ||
               !election.elector_account_hash || !election.elector_code_hash) {
      invalid(out.accepted, "final_cur_elect_provenance_mismatch");
    } else {
      out.accepted.status = Status::ready;
      out.accepted.reason.clear();
      out.accepted.value = election.accepted_nanoton;
      out.accepted.vset_hash = election.config36_hash;
      out.accepted.source_root_hash = election.current_root_hash;
      out.accepted.elector_account_hash = election.elector_account_hash;
      out.accepted.elector_code_hash = election.elector_code_hash;
      out.accepted.election_id = election.current_election_id;
      for (const auto &c : election.candidates)
        out.accepted.validators.push_back({c.pubkey, c.raw_holder, c.adnl,
            std::nullopt, std::nullopt, c.stake_nanoton, std::nullopt});
    }
  } else if (election.applications.status == election::Status::pending &&
             !election.applications.reason.empty()) {
    out.accepted.reason = election.applications.reason;
  }
  // Deliberately NO RoundYield bridge: neither this single-state extractor nor
  // ElectionBoundary proves an isolated Elector tx, full before/after credits
  // delta, or complete selection->pre-unfreeze continuity. Supplying strings
  // or toggling RoundYield::Provenance booleans would fabricate APR/APY.
  return out;
}

}  // namespace

Output run(const schema::MasterchainBlockDataState &loaded, const Input &input) {
  if (anchor_gate(input) != Gate::verified) {
    // Do not even invoke the existing extractors with state_update_verified
    // until all required structured evidence is bound to this anchor.
    return project(input, {}, {});
  }
  analytics::validators::Input snap_input;
  snap_input.network_zerostate = input.network_zerostate;
  snap_input.expected_mc_id = input.expected_mc_id;
  snap_input.expected_state_hash = input.expected_post_state_root;
  snap_input.state_update_verified = true;
  snap_input.supported_elector_code_hashes = input.supported_elector_code_hashes;
  auto snapshot = extract_validator_snapshot(loaded, snap_input);

  election::Input election_input;
  election_input.network_zerostate = input.network_zerostate;
  election_input.expected_mc_id = input.expected_mc_id;
  election_input.expected_state_hash = input.expected_post_state_root;
  election_input.state_update_verified = true;
  election_input.supported_elector_code_hashes = input.supported_elector_code_hashes;
  if (input.election_boundary) {
    election_input.election_id = input.election_boundary->election_id;
    election_input.expected_vset_hash = input.election_boundary->selected_vset_hash;
  }
  auto observation = election::observe_election(loaded, election_input);
  // An error in one independently extracted metric family cannot erase the
  // other family's facts. The failed family carries pending, never zero.
  Snapshot snap;
  if (snapshot.is_ok()) {
    snap = snapshot.move_as_ok();
  } else {
    snap.network_zerostate = input.network_zerostate;
    snap.mc_id = input.expected_mc_id;
    snap.state_hash = input.expected_post_state_root;
    snap.state_update_verified = true;
    snap.count.reason = "snapshot_extraction_error";
    snap.frozen_remaining.reason = "snapshot_extraction_error";
  }
  election::Observation observed;
  if (observation.is_ok()) {
    observed = observation.move_as_ok();
  } else {
    observed.network_zerostate = input.network_zerostate;
    observed.mc_id = input.expected_mc_id;
    observed.state_hash = input.expected_post_state_root;
    observed.state_update_verified = true;
    observed.roster.reason = "election_extraction_error";
    observed.past.reason = "election_extraction_error";
    observed.applications.reason = "election_extraction_error";
  }
  return project(input, snap, observed);
}

namespace testing {
Output project_synthetic(const Input &input, const Snapshot &snapshot,
                         const election::Observation &observation) {
  return project(input, snapshot, observation);
}
}  // namespace testing

}  // namespace analytics::validators::stage
