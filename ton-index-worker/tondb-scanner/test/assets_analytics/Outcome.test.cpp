#include "../../src/assets_analytics/Outcome.h"

#include <cassert>
#include <limits>
#include <string>

using namespace assets_analytics;

static Observation fixture() {
  Observation o;
  o.wallet = {AccountLookup::found, "0:wallet", "state-w", "code-w", "data-w", "active", "20", "extra-w"};
  o.master = {AccountLookup::found, "0:master", "state-m", "code-m", "data-m", "active", "10", ""};
  o.source.network = "testnet";
  o.source.zerostate = "test-zerostate";
  o.source.mc_block_id = "mc:A:root:file";
  o.source.mc_state_root_hash = "mc-state-root";
  o.source.current_shard_tips = {{"tip:A:root:file", "wallet-root"},
                                  {"tip:B:root:file", "master-root"},
                                  {"tip:C:root:file", "unrelated-root"}};
  o.source.tip_manifest_sha256 = "manifest-1";
  o.source.tip_block_id = "tip:A:root:file";
  o.source.tip_state_root_hash = "wallet-root";
  o.source.master_tip_block_id = "tip:B:root:file";
  o.source.master_tip_state_root_hash = "master-root";
  o.source.config_hash = "config";
  o.source.historical_now = 12345;
  o.source.caller_attests_state_updates = true;
  o.source.caller_attests_manifest_complete = true;
  o.source.caller_attests_config_from_mc = true;
  o.owner = "0:owner";
  o.master_address = o.master.address;
  o.getter_wallet_code_hash = "getter-code";
  o.raw_signed_balance = "10";
  o.binding = Binding::matched;
  o.master_returned_wallet = o.wallet.address;
  return o;
}

static GetterContextAudit audited(const Observation& o) {
  GetterContextAudit a;
  a.report_id = "reviewed-jetton-code-and-method-dependencies:v1";
  a.report_sha256 = std::string(64, 'a');
  a.allowlist_policy_version = "v1";
  a.c7_dependency_assessment = "audited_independent_of_unavailable_c7_fields";
  a.wallet_address = o.wallet.address;
  a.wallet_state_hash = o.wallet.state_hash;
  a.wallet_code_hash = o.wallet.code_hash;
  a.master_address = o.master.address;
  a.master_state_hash = o.master.state_hash;
  a.master_code_hash = o.master.code_hash;
  a.mc_block_id = o.source.mc_block_id;
  a.mc_state_root_hash = o.source.mc_state_root_hash;
  a.tip_manifest_sha256 = o.source.tip_manifest_sha256;
  a.current_shard_tips = o.source.current_shard_tips;
  a.config_hash = o.source.config_hash;
  a.historical_now = o.source.historical_now;
  a.wallet_method = "get_wallet_data";
  a.master_method = "get_wallet_address";
  a.audited_vm_context_limits = o.source.vm_context_limits;
  return a;
}

int main() {
  Observation o = fixture();
  assert(o.wallet.lookup == AccountLookup::found && classify(o) == Status::unknown);
  // Even matching get_wallet_address + nonnegative raw balance isn't verified without an audit.
  o.raw_signed_balance = "0";
  assert(classify(o) == Status::unknown);
  o.context_audit = audited(o);
  assert(classify(o) == Status::found);  // zero is observed, not a positive-balance count
  o.raw_signed_balance = "340282366920938463463374607431768211455";
  assert(classify(o) == Status::found);  // no signed int64 narrowing
  o.raw_signed_balance = "-1";
  assert(classify(o) == Status::unknown);
  o.raw_signed_balance = "NaN";
  assert(classify(o) == Status::unknown);
  o.raw_signed_balance = "10";

  o.owner = "";
  assert(classify(o) == Status::unknown);
  o.owner.reset();
  assert(classify(o) == Status::unknown);
  o.owner = "0:owner";
  o.master_address = "";
  assert(classify(o) == Status::unknown);
  o.master_address.reset();
  assert(classify(o) == Status::unknown);
  o.master_address = "0:unrelated-master";
  assert(classify(o) == Status::unknown);
  o.master_address = o.master.address;
  o.getter_wallet_code_hash = "";
  assert(classify(o) == Status::unknown);
  o.getter_wallet_code_hash = "getter-code";
  assert(classify(o) == Status::found);

  o.binding = Binding::unmatched;
  assert(classify(o) == Status::unknown);
  o.binding = Binding::matched;
  o.master_returned_wallet = "0:other";
  assert(classify(o) == Status::unknown);
  o.master_returned_wallet = o.wallet.address;
  o.master.lookup = AccountLookup::not_present;
  assert(classify(o) == Status::unknown);
  o.master.lookup = AccountLookup::error;
  assert(classify(o) == Status::error);
  o.master.lookup = AccountLookup::found;

  o.source.caller_attests_manifest_complete = false;
  assert(classify(o) == Status::unknown);
  o.source.caller_attests_manifest_complete = true;
  o.source.caller_attests_state_updates = false;
  assert(classify(o) == Status::unknown);
  o.source.caller_attests_state_updates = true;
  o.source.caller_attests_config_from_mc = false;
  assert(classify(o) == Status::unknown);
  o.source.caller_attests_config_from_mc = true;
  o.source.vm_context_limits = "unknown-C7";
  assert(classify(o) == Status::unknown);
  o.source.vm_context_limits = "native_c7_lt_zero_seed_zero_prev_blocks_absent";
  o.context_audit->master_code_hash = "stale-master-code";
  assert(classify(o) == Status::unknown);
  o.context_audit = audited(o);
  o.context_audit->c7_dependency_assessment = "not_yet_audited";
  assert(classify(o) == Status::unknown);
  o.context_audit = audited(o);
  o.context_audit->report_sha256 = "not-a-sha256";
  assert(classify(o) == Status::unknown);
  o.context_audit = audited(o);
  o.context_audit->wallet_method = "get_jetton_data";
  assert(classify(o) == Status::unknown);
  o.context_audit = audited(o);
  o.context_audit->historical_now += 1;
  assert(classify(o) == Status::unknown);
  o.context_audit = audited(o);
  o.context_audit->wallet_state_hash = "older-wallet-state";
  assert(classify(o) == Status::unknown);
  o.context_audit = audited(o);
  o.context_audit->config_hash = "different-config";
  assert(classify(o) == Status::unknown);
  o.context_audit = audited(o);
  o.source.current_shard_tips.back().state_root_hash = "changed-unrelated-tip";
  assert(classify(o) == Status::unknown); // full manifest, not just wallet/master tips
  o.source = fixture().source;
  assert(classify(o) == Status::found);
  assert(o.source.current_shard_tips.size() == 3);
  assert(o.source.current_shard_tips[2].block_id == "tip:C:root:file");
  auto reordered = o.source.current_shard_tips;
  std::reverse(reordered.begin(), reordered.end());
  assert(canonical_tip_manifest(reordered) == canonical_tip_manifest(o.source.current_shard_tips));
  reordered[0].state_root_hash = "changed-root";
  assert(canonical_tip_manifest(reordered) != canonical_tip_manifest(o.source.current_shard_tips));

  o.wallet.lookup = AccountLookup::not_present;
  assert(classify(o) == Status::not_present);
  o.source.caller_attests_manifest_complete = false;
  assert(classify(o) == Status::unknown); // unproved absence is NOT not_present
  assert(!Observation::is_global_snapshot_complete);

  // The audit and all materialized manifest copies share ONE cap. A former
  // pair of independent <=cap checks would incorrectly accept the 55 case.
  assert(!fits_aggregate_provenance_budget(6, 10, 2, 55));
  assert(fits_aggregate_provenance_budget(6, 10, 2, 56));
  assert(fits_aggregate_provenance_budget(15, 10, 0, 25));
  assert(!fits_aggregate_provenance_budget(15, 10, 0, 24));
  assert(!fits_aggregate_provenance_budget(1, 0, 2, 100));
  assert(!fits_aggregate_provenance_budget(std::numeric_limits<size_t>::max(), 1, 1,
                                           std::numeric_limits<size_t>::max()));
  assert(!fits_aggregate_provenance_budget(1, std::numeric_limits<size_t>::max(), 1,
                                           std::numeric_limits<size_t>::max()));
}
