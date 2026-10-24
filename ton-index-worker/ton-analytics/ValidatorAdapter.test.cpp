#include "Adapters.h"
#include "../ton-analytics-validators/ValidatorCoreBridge.h"

#include <algorithm>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <utility>

namespace core = tonstat::core;
namespace runner = tonstat::runner;
namespace validators = analytics::validators;
namespace stage = validators::stage;
namespace election = validators::election;

namespace {
void expect(bool ok, const std::string& message) {
  if (!ok) throw std::runtime_error(message); // active in Release / NDEBUG builds
}
bool has(const std::string& text, const std::string& part) { return text.find(part) != std::string::npos; }
td::Bits256 hash(unsigned char byte) {
  td::Bits256 result{};
  result.as_array().fill(byte);
  return result;
}
ton::BlockIdExt mc(uint32_t seq) {
  return {ton::masterchainId, ton::shardIdAll, seq, hash(seq), hash(seq + 40)};
}
std::vector<td::Bits256> allowed_codes() {
  return {runner::bits(std::string(validators::kReviewedElectorCodeHash))};
}

// Explicitly SYNTHETIC proof metadata: no archive, BoC authentication, native
// positive verification, or production evidence is claimed by this fixture.
core::AnchorEvidence synthetic_core(uint32_t seq = 23) {
  core::AnchorEvidence e;
  e.status = core::Status::verified_local_archive;
  e.scope = core::Scope::auxiliary_mc_only;
  e.snapshot_integrity_checked = true;
  e.network = "mainnet";
  e.pin.zerostate = *core::testing::trusted_mc0(-239);
  e.mc_state_zerostate = e.pin.zerostate;
  e.mc = {mc(seq), hash(seq + 80), hash(seq + 79), hash(seq + 80), -239, 1788220800};
  e.mc_predecessors = {mc(seq - 1)};
  const auto subject = e.mc.id.to_str();
  e.checks = {
      {"full_id_handle_block_data_and_original_boc_sha256", subject, e.mc.id.file_hash.to_hex()},
      {"raw_block_root_and_header", subject, e.mc.id.root_hash.to_hex()},
      {"merkle_update_new_equals_typed_post_state", subject, e.mc.state_root.to_hex()},
      {"external_pin_and_mc_state_mc0_match_trusted_network", subject, e.pin.zerostate.to_str()},
      {"network_from_raw_mc_global_id", subject, e.network},
      {"raw_mc_header_full_predecessor", subject, e.mc_predecessors.front().to_str()}};
  return e;
}
stage::Input map(const core::AnchorEvidence& e, const ton::BlockIdExt& expected, const core::NetworkPin& pin) {
  return tonstat::validators::testing::map_synthetic_core(e, expected, pin, allowed_codes());
}
stage::Input map(const core::AnchorEvidence& e) { return map(e, e.mc.id, e.pin); }
validators::Snapshot snapshot(const stage::Input& in) {
  validators::Snapshot s;
  s.network_zerostate = in.network_zerostate;
  s.mc_id = in.expected_mc_id; s.state_hash = in.expected_post_state_root;
  s.state_update_verified = true; s.gen_utime = 1788220800;
  s.config34_hash = hash(5); s.total = 2; s.main = 1; s.total_weight = 150;
  s.utime_since = 1788220000; s.utime_until = 1788300000;
  s.members = {{0, hash(10), 50, std::nullopt}, {1, hash(11), 100, hash(12)}};
  validators::validate_roster(s);
  s.frozen_remaining.reason = "elector_code_not_reviewed";
  return s;
}
election::Observation observation(const stage::Input& in) {
  election::Observation o;
  o.network_zerostate = in.network_zerostate;
  o.mc_id = in.expected_mc_id; o.state_hash = in.expected_post_state_root;
  o.state_update_verified = true; o.gen_utime = 1788220800;
  o.applications.reason = "current_election_not_final";
  return o;
}
stage::Output project(const stage::Input& in) {
  return stage::testing::project_synthetic(in, snapshot(in), observation(in));
}
runner::Rows rows() {
  const auto e = synthetic_core();
  runner::Options options;
  options.zero_root = e.pin.zerostate.root_hash.to_hex();
  options.zero_file = e.pin.zerostate.file_hash.to_hex();
  return {options, "synthetic-adapter-regression", e};
}
std::string render(const stage::Output& out, bool success) {
  auto r = rows();
  const auto error = runner::write_validators(r, out);
  expect(error.empty() == success, "unexpected runner metric readiness: " + error);
  expect(has(r.text(), "\"daily_complete\":false"), "single MC must not close a day");
  expect(has(r.text(), "\"publication_ready\":false"), "single MC must not claim publication");
  expect(!has(r.text(), "native_chain_verified"), "local checks are not chain verification");
  return r.text();
}
void regression_failure(stage::Output out, const std::function<void(stage::Output&)>& mutate) {
  mutate(out);
  auto r = rows();
  try { (void)runner::write_validators(r, out); }
  catch (const std::invalid_argument& e) {
    expect(std::string(e.what()) == "ready check has a failure reason", "unexpected renderer rejection");
    expect(r.text().empty(), "failed rendering must not append a partial row");
    return;
  }
  throw std::runtime_error("old adapter's ready+reason regression was not reproduced");
}

void count_and_check_regressions() {
  const auto e = synthetic_core();
  auto out = project(map(e));
  // Pass the bridge's typed output through the same runner input adapter used
  // for adjacent extraction, then through the actual runner->domain renderer.
  const auto in = runner::validator_input(out);
  out = project(in);
  expect(out.count.status == stage::Status::ready && out.count.value == "2", "matching #34 count missing");
  for (const auto* c : {&in.anchor.raw_block_file_hash, &in.anchor.header_and_predecessor, &in.anchor.state_update})
    expect(c->status == stage::Status::ready && c->reason.empty(), "success check carries a failure reason");
  const auto json = render(out, true);
  expect(has(json, "\"count\":{\"status\":\"ready\",\"reason\":\"\",\"unit\":\"validators\",\"value_decimal\":\"2\""),
         "ready numeric count not rendered");
  expect(has(json, "\"frozen_remaining\":{\"status\":\"pending\",\"reason\":\"elector_code_not_reviewed\",\"unit\":\"nanoton\",\"value_decimal\":null"),
         "optional stake must retain null and reason");
  expect(has(json, "\"selected_initial\":{\"status\":\"pending\""), "one MC cannot prove election boundary");
  expect(has(json, "\"election_boundary\":null"), "header predecessor is not a boundary");
  regression_failure(out, [](auto& x) { x.anchor.raw_block_file_hash.reason = "core_original_boc_sha256"; });
  regression_failure(out, [](auto& x) { x.anchor.header_and_predecessor.reason = "core_raw_header_full_predecessor"; });
  regression_failure(out, [](auto& x) { x.anchor.state_update.reason = "core_merkle_update_and_typed_state"; });

  const auto rejected = [&](const core::AnchorEvidence& bad, const ton::BlockIdExt& expected,
                            const core::NetworkPin& pin, const std::string& label) {
    const auto mapped = map(bad, expected, pin);
    expect(mapped.anchor.raw_block_file_hash.status != stage::Status::ready, label + " became ready");
    expect(!mapped.anchor.raw_block_file_hash.reason.empty(), label + " lost its reason");
    const auto first = project(mapped);
    const auto adapted = runner::validator_input(first);
    expect(adapted.anchor.raw_block_file_hash.reason == mapped.anchor.raw_block_file_hash.reason,
           label + " adapter erased core reason");
    const auto result = project(adapted);
    expect(!result.count.value && result.count.validators.empty(), label + " retained numeric facts");
    if (result.post_state_root != td::Bits256{} && expected.is_masterchain() && expected.is_valid_full()) {
      const auto text = render(result, false);
      expect(has(text, "\"value_decimal\":null"), label + " missing null");
      expect(!has(text, "\"status\":\"ready\""), label + " rendered ready");
    }
  };
  // Each required code must match BOTH its full-ID subject and copied observed
  // digest/ID. Retaining a code name or verified status alone is insufficient.
  for (size_t i = 0; i < e.checks.size(); ++i) {
    for (int mutation = 0; mutation < 4; ++mutation) {
      auto bad = e;
      const auto label = e.checks[i].code + "/" + std::to_string(mutation);
      if (mutation == 0) bad.checks[i].observed.clear();
      if (mutation == 1) bad.checks[i].observed = hash(99).to_hex();
      if (mutation == 2) bad.checks[i].subject = mc(24).to_str();
      if (mutation == 3) bad.checks.erase(bad.checks.begin() + i);
      rejected(bad, e.mc.id, e.pin, label);
    }
  }
  const std::vector<std::function<void(core::AnchorEvidence&)>> mutations = {
      [](auto& x) { x.mc.id.file_hash = hash(99); },
      [](auto& x) { x.mc.id.root_hash = hash(99); },
      [](auto& x) { x.mc.state_root = hash(99); },
      [](auto& x) { x.mc.state_update_new = hash(99); },
      [](auto& x) {
        // Pinned BitArray has pointer/bit-view assignment overloads; use its
        // explicit zeroing API rather than ambiguous empty-brace assignment.
        x.mc.state_root.set_zero();
        expect(x.mc.state_root.is_zero(), "zero-state-root mutation did not clear the hash");
      },
      [](auto& x) { x.mc.global_id = -3; },
      [](auto& x) { x.network = "testnet"; },
      [](auto& x) { x.pin.zerostate.root_hash = hash(99); },
      [](auto& x) { x.pin.zerostate.file_hash = hash(99); },
      [](auto& x) { x.mc_state_zerostate.reset(); },
      [](auto& x) { x.mc_state_zerostate->file_hash = hash(99); },
      [](auto& x) { x.snapshot_integrity_checked = false; },
      [](auto& x) { x.scope = core::Scope::full_snapshot; },
      [](auto& x) { x.mc_predecessors.clear(); },
      [](auto& x) { x.mc_predecessors.front() = mc(21); },
      [](auto& x) { x.issues.push_back({"missing_input", "test fixture"}); }};
  for (size_t i = 0; i < mutations.size(); ++i) {
    auto bad = e; mutations[i](bad);
    rejected(bad, e.mc.id, e.pin, "identity/" + std::to_string(i));
  }
  auto expected = e.mc.id; expected.file_hash = hash(99);
  rejected(e, expected, e.pin, "externally_selected_full_id");
  expected = e.mc.id; expected.id.workchain = 0;
  rejected(e, expected, e.pin, "not_mc");
  auto pin = e.pin; pin.zerostate.file_hash = hash(99);
  rejected(e, e.mc.id, pin, "external_pin_file");
  // Even internally consistent arbitrary MC0 metadata is not a trusted pin.
  auto arbitrary = e; arbitrary.pin = pin; arbitrary.mc_state_zerostate = pin.zerostate;
  arbitrary.checks[3].observed = pin.zerostate.to_str();
  rejected(arbitrary, e.mc.id, pin, "self_consistent_untrusted_pin");
  for (auto status : {core::Status::incomplete, core::Status::error}) {
    auto pending = e; pending.status = status;
    pending.issues = {{"missing_archive_state", "fixture dependency absent"}};
    rejected(pending, e.mc.id, e.pin, "unresolved_core");
    const auto mapped = map(pending);
    expect(mapped.anchor.state_update.status == (status == core::Status::incomplete ? stage::Status::pending : stage::Status::invalid),
           "pending/error distinction lost");
    expect(has(mapped.anchor.state_update.reason, "missing_archive_state"), "actual pending source reason lost");
  }
}

void boundary_regressions() {
  auto e = synthetic_core();
  const auto previous_e = synthetic_core(22);
  auto current = runner::validator_input(project(map(e)));
  const auto previous = runner::validator_input(project(map(previous_e)));
  e.scope = core::Scope::full_snapshot;
  e.continuity_status = core::Status::verified_local_archive; e.continuity_reason.clear();
  e.previous_mc = previous.expected_mc_id; e.previous_mc_state_root = previous.expected_post_state_root;
  e.checks.push_back({"adjacent_mc_predecessor_full_id_and_state_update_old", e.mc.id.to_str(),
                      e.previous_mc->to_str() + " / " + e.previous_mc_state_root->to_hex()});
  auto now = observation(current);
  now.config36_hash = hash(6); now.requested_vset_hash = now.config36_hash; now.requested_election_id = 1788220000;
  now.past = {election::Status::ready, ""}; now.past_present = true;
  now.roster = {election::Status::ready, ""}; now.total = 1; now.main = 1; now.total_weight = 50;
  now.since = 1788220000; now.until = 1788300000;
  now.elected = {{0, hash(10), 50, std::nullopt}};
  now.frozen = {{hash(10), hash(20), 50, "1000", false}};
  now.frozen_total_nanoton = "1000"; now.bonuses_nanoton = "0";
  now.unfreeze_at = 1788400000; now.stake_held_for = 100;
  now.past_root_hash = hash(7); now.frozen_root_hash = hash(8); now.elector_account_hash = hash(9);
  now.elector_code_hash = allowed_codes().front();
  auto prior = observation(previous);
  prior.requested_election_id = now.requested_election_id; prior.requested_vset_hash = now.config36_hash;
  prior.past = {election::Status::ready, ""}; prior.past_present = false;
  current.election_boundary = runner::validator_boundary(e, current, previous, std::nullopt, now, prior);
  expect(current.election_boundary.has_value(), "valid adjacent first-frozen boundary missing");
  auto out = stage::testing::project_synthetic(current, snapshot(current), now);
  expect(out.selected_initial.status == stage::Status::ready && out.selected_initial.value == "1000",
         "verified synthetic boundary lost useful selected stake");
  auto json = render(out, true);
  expect(has(json, "\"selected_initial\":{\"status\":\"ready\",\"reason\":\"\""), "boundary did not render");
  regression_failure(out, [](auto& x) {
    x.election_boundary->first_post_election.reason = "adjacent_config36_transition_and_prior_frozen_absent";
  });
  regression_failure(out, [](auto& x) {
    x.election_boundary->previous_state_and_config36.reason = "core_verified_previous_state_config36_decoded";
  });
  const std::vector<std::function<void(core::AnchorEvidence&)>> mutations = {
      [](auto& x) { x.continuity_status = core::Status::incomplete; },
      [](auto& x) { x.scope = core::Scope::auxiliary_mc_only; },
      [](auto& x) { x.previous_mc->file_hash = hash(99); },
      [](auto& x) { x.previous_mc_state_root = hash(99); },
      [](auto& x) { x.mc.state_update_old = hash(99); },
      [](auto& x) { x.mc_predecessors.front() = mc(21); },
      [](auto& x) { x.checks.back().observed.clear(); },
      [](auto& x) { x.checks.back().observed = hash(99).to_hex(); },
      [](auto& x) { x.checks.back().subject = mc(24).to_str(); },
      [](auto& x) { x.checks.pop_back(); }};
  for (const auto& mutate : mutations) {
    auto bad = e; mutate(bad);
    expect(!runner::validator_boundary(bad, current, previous, std::nullopt, now, prior), "invalid adjacent proof promoted");
  }
  expect(!runner::validator_boundary(e, current, previous, now.config36_hash, now, prior), "unchanged #36 is not a boundary");
  expect(runner::validator_boundary(e, current, previous, hash(4), now, prior).has_value(), "changed nonempty prior #36 rejected");
  for (const auto& mutate : std::vector<std::function<void(election::Observation&)>>{
           [](auto& x) { x.past_present = true; },
           [](auto& x) { x.past_present.reset(); },
           [](auto& x) { x.past.status = election::Status::pending; },
           [](auto& x) { x.requested_election_id = 1; },
           [](auto& x) { x.requested_vset_hash = hash(99); },
           [](auto& x) { x.state_hash = hash(99); },
           [](auto& x) { x.mc_id = mc(21); },
           [](auto& x) { x.state_update_verified = false; }}) {
    auto bad = prior; mutate(bad);
    expect(!runner::validator_boundary(e, current, previous, std::nullopt, now, bad), "unproved prior absence promoted");
  }
  auto unresolved = previous; unresolved.anchor.state_update = {};
  expect(!runner::validator_boundary(e, current, unresolved, std::nullopt, now, prior), "unverified prior anchor promoted");
  // Snapshot count stays ready when adjacent/election evidence is absent.
  current.election_boundary.reset();
  out = stage::testing::project_synthetic(current, snapshot(current), now);
  expect(out.count.status == stage::Status::ready && out.selected_initial.status == stage::Status::pending,
         "missing boundary incorrectly hides count or invents original stake");
  render(out, true);
}

void native_fail_closed() {
  // The production runner must enter the native verifier, not accept our forged
  // ready metadata. Missing raw MC input cannot produce any numeric row.
  const auto e = synthetic_core();
  auto r = rows();
  bool refused = false;
  try { refused = !runner::validators(r, {}, e).empty(); }
  catch (const std::invalid_argument&) { refused = true; } // renderer lacks verified state provenance
  expect(refused && r.text().empty(), "production runner trusted synthetic metadata without raw MC data");
  const auto result = tonstat::validators::run_verified_mc({}, e.mc.id, e.pin, allowed_codes());
  expect(!result.core && !result.stage.count.value && result.stage.count.status != stage::Status::ready,
         "native empty-MC path invented a count");
}
} // namespace

int main() {
  try {
    count_and_check_regressions();
    boundary_regressions();
    native_fail_closed();
    std::cout << "validator adapter: synthetic mapping/render/boundary regressions and native missing-input gate passed\n";
    return 0;
  } catch (const std::exception& e) {
    std::cerr << "validator adapter regression: " << e.what() << '\n';
    return 1;
  }
}
