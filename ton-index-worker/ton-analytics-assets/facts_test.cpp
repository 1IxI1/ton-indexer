#ifdef NDEBUG
#undef NDEBUG
#endif
#include "AssetFacts.h"

#include <cassert>
#include <stdexcept>
#include <string>

using namespace assets_analytics;

static BatchMeta meta() {
  return {"testnet", "zerostate", "v1", "-1:mc:root:file", "mc-state", 12345, "zerostate-file"};
}

static Observation fixture(std::string wallet = "0:wallet") {
  Observation o;
  o.wallet = {AccountLookup::found, wallet, "wallet-state", "wallet-code", "wallet-data", "active", "20", "extra"};
  o.master = {AccountLookup::found, "0:master", "master-state", "master-code", "master-data", "active", "10", ""};
  o.source.network = "testnet";
  o.source.zerostate = "zerostate";
  o.source.mc_block_id = "-1:mc:root:file";
  o.source.mc_state_root_hash = "mc-state";
  o.source.current_shard_tips = {{"0:tip1:root:file", "wallet-root"},
                                 {"0:tip2:root:file", "master-root"},
                                 {"0:unrelated:root:file", "other-root"}};
  o.source.tip_manifest_sha256 = std::string(64, 'a');
  o.source.tip_block_id = "0:tip1:root:file";
  o.source.tip_state_root_hash = "wallet-root";
  o.source.master_tip_block_id = "0:tip2:root:file";
  o.source.master_tip_state_root_hash = "master-root";
  o.source.config_hash = "config";
  o.source.historical_now = 12345;
  o.source.caller_attests_state_updates = true;
  o.source.caller_attests_manifest_complete = true;
  o.source.caller_attests_config_from_mc = true;
  o.raw_signed_balance = "340282366920938463463374607431768211455";
  o.owner = "0:owner";
  o.master_address = "0:master";
  o.getter_wallet_code_hash = "getter-wallet-code";
  o.master_returned_wallet = wallet;
  o.binding = Binding::matched;
  return o;
}

static GetterContextAudit audit_for(const Observation& o) {
  GetterContextAudit a;
  a.report_id = "independent-review";
  a.report_sha256 = std::string(64, 'b');
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

static bool has(const std::string& s, const std::string& part) {
  return s.find(part) != std::string::npos;
}

// Public metadata only, copied from replay-6x4opv_y-verified/spool/
// {92976409,92976410}.committed/facts.ndjson (TON afe8bfb). No account BoC,
// NodeDB, getter result, or context audit is invented by this fixture. The
// renderer overwrote the extractor's original reason, so it is unknowable here.
static Observation replay_observation(bool successor) {
  Observation o;
  o.status = Status::error;
  o.wallet = {AccountLookup::found,
      "0:4A44CB486DE15BAD57B4BD470EC51D81B427B944D2EE4C0250CE72D6AB6C82F2",
      "BCEB6BF193A8664BB8EF31B0E5F9C8034C9BBC1479E69C2B49AF99DFFE9F1F88",
      "89468F02C78E570802E39979C8516FC38DF07EA76A48357E0536F2BA7B3EE37B",
      "85696DE7B9C195C24A22FEDF9CFB3100BE1CE4DDE5248B337BCAA7E9CBD45582",
      "active", "5929545", ""};
  auto& p = o.source;
  p.network = "mainnet";
  p.zerostate = "17a3a92992aabea785a7a090985a265cd31f323d849da51239737e321fb05569";
  p.mc_block_id = successor ?
      "(-1,8000000000000000,92976410):32B1911C64AACE68BB56A59D002972ADAEEE3C78422A47E49C495EE5164CDD8B:FEC7668CBD58A51E142CAF27FB1028DF43F20DE8B063015E1C8EDC946DA94896" :
      "(-1,8000000000000000,92976409):F3B8161DBAA3B9F1047A37C377327E667BFD3251043BB9880E0D9DF58E9403C8:804B1FB9E8BC8080899482A1329BF3E67DCB31B564291E00A967DC32D747F0B4";
  p.mc_state_root_hash = successor ?
      "BF056CA6E1E7CDA549FD284B374E52F60969E0371C036092BF3318944D68F02C" :
      "81269A93599F4167C780DA6349045EB55C5270F935A262103E39CA674FCFF9D5";
  p.historical_now = successor ? 1789516800 : 1789516799;
  p.tip_block_id = successor ?
      "(0,8000000000000000,97410700):41B484C2925C5E7D07FAEFD526D9FCC4146C782268FAA75512DBAD89B6179A9A:72167BC43D7F9E2B67ED3D30499A18A7F7848200A1988D0C39B9A913681C4EFD" :
      "(0,8000000000000000,97410699):C908E7664AEE9F501580525B7228F4DC65691A16BCF323E771DD24446B35ED9C:E249FC27B37E5212FF7ACBE9B42B87D26F482B45EA3B63ED73349F1E3330C016";
  p.tip_state_root_hash = successor ?
      "6A0672C6FB1DA8A83797053F839CEF5EA1A105393844022E532640BE2FE3C96B" :
      "566989684E14A604C2DF7C0DF8953F7D5CEAD44E3D9CDB1234E10A3D403ECFDD";
  p.current_shard_tips = {{p.tip_block_id, p.tip_state_root_hash}};
  p.tip_manifest_sha256 = successor ?
      "d0c47110359f06b0c1f6c22e69ec6baf350778a6e4d91d291ddf787d833ba4bc" :
      "a98dad1096db453140075fec1d34ddc8f411d4c4078a27fd25635e2fbb9a1736";
  p.config_hash = "993E4E609E84A16CA1CD4C7DBDF8ADF102BAB533D7B2C278A1BC96E739834584";
  p.caller_attests_state_updates = true;
  p.caller_attests_manifest_complete = true;
  p.caller_attests_config_from_mc = true;
  return o;
}

static BatchMeta replay_meta(bool successor) {
  // BatchMeta as actually captured, including the caller's lowercase state root.
  return {"mainnet", "17a3a92992aabea785a7a090985a265cd31f323d849da51239737e321fb05569",
      "index-pipeline-assets-v1", successor ?
      "(-1,8000000000000000,92976410):32B1911C64AACE68BB56A59D002972ADAEEE3C78422A47E49C495EE5164CDD8B:FEC7668CBD58A51E142CAF27FB1028DF43F20DE8B063015E1C8EDC946DA94896" :
      "(-1,8000000000000000,92976409):F3B8161DBAA3B9F1047A37C377327E667BFD3251043BB9880E0D9DF58E9403C8:804B1FB9E8BC8080899482A1329BF3E67DCB31B564291E00A967DC32D747F0B4",
      successor ? "bf056ca6e1e7cda549fd284b374e52f60969e0371c036092bf3318944d68f02c" :
                  "81269a93599f4167c780da6349045eb55c5270f935a262103e39ca674fcff9d5",
      successor ? 1789516800U : 1789516799U,
      "5e994fcf4d425c0a6ce6a792594b7173205f740a39cd56f537defd28b48a0f6e"};
}

static void replay_provenance() {
  const std::string mismatch = "batch/manifest provenance mismatch or invalid tip";
  for (bool successor : {false, true}) {
    auto m = replay_meta(successor);
    auto o = replay_observation(successor);
    assert(has(render_batch_json(m, {o}), mismatch));
    // Only the MC state-root encoding differs. Full IDs (including root/file
    // hashes), tip hashes and the length-prefixed manifest retain native case.
    assert(m.network == o.source.network && m.zerostate == o.source.zerostate);
    assert(m.mc_full_id == o.source.mc_block_id && m.mc_gen_utime == o.source.historical_now);
    auto normalized = o.source.mc_state_root_hash;
    for (char& c : normalized) if (c >= 'A' && c <= 'F') c += 'a' - 'A';
    assert(normalized == m.mc_state_root_hash);
    assert(canonical_tip_manifest(o.source.current_shard_tips) ==
           "1:159:" + o.source.tip_block_id + "64:" + o.source.tip_state_root_hash);

    // Model the corrected caller, not a case-insensitive relaxation in renderer.
    m.mc_state_root_hash = o.source.mc_state_root_hash;
    auto json = render_batch_json(m, {o});
    assert(!has(json, mismatch));
    assert(has(json, "\"reported_status\":\"error\""));
    assert(has(json, "\"status\":\"error\""));
    assert(has(json, "\"ton_balance_nanoton\":\"5929545\""));
    assert(has(json, "\"raw_signed_jetton_balance\":null"));
    assert(has(json, "\"owner\":null"));
    assert(has(json, "\"binding\":\"untested\""));
    assert(has(json, "\"getter_context_audit\":null"));
    assert(has(json, "\"address_scope_ready\":false"));
    assert(has(json, "\"global_metric_complete\":false"));
    assert(has(json, "\"scope\":\"address_subset_at_anchor\""));
    // This is an injected diagnostic, NOT a recovered original replay reason.
    o.reason = "get_wallet_data failed";
    assert(has(render_batch_json(m, {o}), "\"reason\":\"get_wallet_data failed\""));
    o.status = Status::unknown;
    o.reason = "getter context audit missing/mismatched or invalid balance";
    json = render_batch_json(m, {o});
    assert(!has(json, mismatch));
    assert(has(json, "\"status\":\"unknown\""));
    assert(has(json, "\"reason\":\"" + o.reason + "\""));
    assert(has(json, "\"status\":\"pending\""));

    // Synthetic absence on the real provenance exercises a genuinely usable
    // positive path without fabricating a successful getter or audit.
    o.wallet.lookup = AccountLookup::not_present;
    o.status = Status::not_present;
    o.reason = "wallet absent, inactive or incomplete";
    assert(has(render_batch_json(m, {o}), "\"address_scope_ready\":true"));
    const auto reject = [&](Observation changed, bool batch_mismatch) {
      const auto result = render_batch_json(m, {changed});
      assert(has(result, "\"address_scope_ready\":false"));
      assert(has(result, "\"status\":\"pending\""));
      if (batch_mismatch) assert(has(result, mismatch));
    };
    auto changed = o; changed.source.network = "testnet"; reject(changed, true);
    changed = o; changed.source.zerostate[0] = '0'; reject(changed, true);
    changed = o; changed.source.mc_block_id[0] = '['; reject(changed, true);
    // Full-ID file hash is part of the binding, not just coordinates/root hash.
    changed = o; changed.source.mc_block_id.back() = '0'; reject(changed, true);
    changed = o; changed.source.mc_state_root_hash[0] = '0'; reject(changed, true);
    changed = o; ++changed.source.historical_now; reject(changed, true);
    changed = o; changed.source.tip_block_id.back() = '0'; reject(changed, false);
    changed = o; changed.source.tip_state_root_hash[0] = '0'; reject(changed, false);
    changed = o; changed.source.current_shard_tips.clear(); reject(changed, true);
    changed = o; changed.source.current_shard_tips.push_back(changed.source.current_shard_tips[0]); reject(changed, true);
    changed = o; changed.source.tip_manifest_sha256 = "not-a-digest"; reject(changed, true);
    changed = o; changed.source.config_hash.clear(); reject(changed, false);
    changed = o; changed.source.caller_attests_state_updates = false; reject(changed, false);
    changed = o; changed.source.caller_attests_manifest_complete = false; reject(changed, false);
    changed = o; changed.source.caller_attests_config_from_mc = false; reject(changed, false);

    // Cross-observation manifests/digests must agree, including unrelated tips.
    auto other = o;
    other.wallet.address.back() = '3';
    other.source.tip_manifest_sha256[0] = '0';
    assert(has(render_batch_json(m, {o, other}), mismatch));
    other = o; other.wallet.address.back() = '3';
    other.source.current_shard_tips.push_back(replay_observation(!successor).source.current_shard_tips[0]);
    assert(has(render_batch_json(m, {o, other}), mismatch));

    // Synthetic successful getters + audit: test the audit gate against the
    // captured config/time/tip encoding. These are NOT replayed Jetton facts.
    auto audited = fixture(o.wallet.address);
    audited.source = o.source;
    audited.source.master_tip_block_id = o.source.tip_block_id;
    audited.source.master_tip_state_root_hash = o.source.tip_state_root_hash;
    audited.status = Status::found;
    audited.context_audit = audit_for(audited);
    assert(has(render_batch_json(m, {audited}), "\"address_scope_ready\":true"));
    changed = audited; changed.context_audit.reset(); reject(changed, false);
    changed = audited; changed.source.config_hash[0] = '0'; reject(changed, false);
    changed = audited; ++changed.context_audit->historical_now; reject(changed, false);
    changed = audited; changed.context_audit->current_shard_tips[0].state_root_hash[0] = '0'; reject(changed, false);
    changed = audited; changed.context_audit->mc_block_id.back() = '0'; reject(changed, false);
  }
}

static void invalid(const BatchMeta& m, const std::vector<Observation>& o) {
  try {
    (void)render_batch_json(m, o);
  } catch (const std::invalid_argument&) {
    return;
  }
  assert(false && "expected invalid_argument");
}

static void oversized(const BatchMeta& m, const std::vector<Observation>& o) {
  try {
    (void)render_batch_json(m, o);
  } catch (const std::length_error&) {
    return;
  }
  assert(false && "expected length_error");
}

int main() {
  replay_provenance();
  auto m = meta();
  auto a = fixture();
  // A raw getter value (including 0) without audit must not become a verified fact.
  a.status = Status::found;
  auto json = render_batch_json(m, {a});
  assert(has(json, "\"status\":\"unknown\""));
  assert(has(json, "\"reported_status\":\"found\""));
  assert(has(json, "\"status\":\"pending\""));
  assert(has(json, "\"raw_signed_jetton_balance\":\"340282366920938463463374607431768211455\""));
  assert(!has(json, "\"raw_signed_jetton_balance\":340282366920938463463374607431768211455"));
  assert(has(json, "\"full_block_id\":\"0:unrelated:root:file\""));
  assert(has(json, "\"writer_committed\":false"));
  assert(has(json, "\"publication_ready\":false"));
  assert(has(json, "\"readiness_basis\":\"caller_attested_only\""));
  assert(has(json, "\"zerostate_file_hash\":\"zerostate-file\""));
  assert(has(json, "\"global_metric_complete\":false"));
  assert(has(json, "\"daily_complete\":false"));
  assert(has(json, "\"getter_context_audit\":null"));

  a.context_audit = audit_for(a);
  json = render_batch_json(m, {a});
  assert(has(json, "\"status\":\"found\""));
  assert(has(json, "\"status\":\"address_scope_ready\""));
  assert(has(json, "\"address_scope_ready\":true"));
  assert(has(json, "\"readiness_basis\":\"caller_attested_only\""));
  assert(has(json, "\"publication_ready\":false"));
  assert(has(json, "\"writer_committed\":false"));
  assert(has(json, "\"report_sha256\":\"" + std::string(64, 'b') + "\""));
  assert(has(json, "\"wallet\":{\"lookup\":\"found\""));
  assert(has(json, "\"master\":{\"lookup\":\"found\""));
  assert(has(json, "\"mc_full_id\":\"-1:mc:root:file\""));

  a.raw_signed_balance = "0";
  json = render_batch_json(m, {a});
  assert(has(json, "\"raw_signed_jetton_balance\":\"0\""));
  assert(has(json, "\"status\":\"found\""));
  a.raw_signed_balance.reset();
  json = render_batch_json(m, {a});
  assert(has(json, "\"raw_signed_jetton_balance\":null"));
  assert(has(json, "\"status\":\"pending\""));
  a.raw_signed_balance = "-1";
  json = render_batch_json(m, {a});
  assert(has(json, "\"raw_signed_jetton_balance\":\"-1\""));
  assert(has(json, "\"status\":\"unknown\""));
  a.raw_signed_balance = "10";
  a.context_audit->config_hash = "stale";
  assert(has(render_batch_json(m, {a}), "\"status\":\"pending\""));

  auto missing = fixture("0:absent");
  missing.wallet.lookup = AccountLookup::not_present;
  missing.status = Status::not_present;
  assert(has(render_batch_json(m, {missing}), "\"status\":\"address_scope_ready\""));
  missing.source.caller_attests_manifest_complete = false;
  assert(has(render_batch_json(m, {missing}), "\"status\":\"pending\""));
  missing = fixture("0:absent");
  missing.status = Status::error;
  missing.reason = "lookup failed\nretry";
  missing.wallet.lookup = AccountLookup::error;
  missing.raw_signed_balance.reset();
  assert(has(render_batch_json(m, {missing}), "\"reason\":\"lookup failed\\nretry\""));
  assert(has(render_batch_json(m, {missing}), "\"status\":\"error\""));

  auto b = fixture("0:another");
  b.context_audit = audit_for(b);
  b.status = Status::found;
  a = fixture("0:wallet");
  a.context_audit = audit_for(a);
  a.status = Status::found;
  assert(render_batch_json(m, {a, b}) == render_batch_json(m, {b, a}));
  invalid(m, {a, a});
  auto empty = fixture("");
  invalid(m, {empty});
  assert(has(render_batch_json(m, {}), "\"status\":\"pending\""));
  m.calc_version.clear();
  invalid(m, {a});
  m.calc_version = "v1\nunsafe";
  invalid(m, {a});
  m = meta();
  m.mc_full_id.clear();
  invalid(m, {a});
  m = meta();
  m.mc_gen_utime = 0;
  invalid(m, {a});
  m = meta();
  m.zerostate_file_hash.clear();
  invalid(m, {a});
  // Legacy six-field aggregate initializers compile but may not emit a batch.
  BatchMeta old_shape{"testnet", "zerostate", "v1", "-1:mc:root:file", "mc-state", 12345};
  invalid(old_shape, {a});

  m = meta();
  a = fixture();
  a.reason = std::string(300000, 'x');
  oversized(m, {a});  // large untrusted input, before canonical manifest construction
  a.reason = std::string(45000, '\x01');
  oversized(m, {a});  // escaped output exceeds 256 KiB although raw input does not
  a = fixture();
  a.source.current_shard_tips.resize(9000, {"same-tip", "same-root"});
  oversized(m, {a});
  std::vector<Observation> many;
  for (int i = 0; i < 400; ++i) many.push_back(fixture("0:wallet-" + std::to_string(i)));
  oversized(m, many);  // cumulative JSON overhead, not one oversize field

  m = meta();
  a = fixture();
  a.context_audit = audit_for(a);
  a.status = Status::found;
  a.reason = "quote \" slash \\ tab\t ctrl\x01";
  a.owner = std::string("bad\xFF", 4);
  json = render_batch_json(m, {a});
  assert(has(json, "\"reason\":\"quote \\\" slash \\\\ tab\\t ctrl\\u0001\""));
  assert(has(json, "\"owner\":\"bad\\u00ff\""));
  assert(json.size() <= 256 * 1024);
  m.zerostate_file_hash = "file\"\\\n";
  assert(has(render_batch_json(m, {a}), "\"zerostate_file_hash\":\"file\\\"\\\\\\n\""));
  a.source.mc_block_id = "wrong anchor";
  assert(has(render_batch_json(m, {a}), "\"status\":\"pending\""));
  a = fixture();
  a.context_audit = audit_for(a);
  a.status = Status::found;
  a.source.current_shard_tips.back().state_root_hash = "changed";
  assert(has(render_batch_json(m, {a}), "\"status\":\"pending\""));
}
