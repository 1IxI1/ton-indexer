#include "AssetEventStage.h"

#include <algorithm>
#include <cassert>
#include <iostream>
#include <stdexcept>

#ifdef NDEBUG
#undef assert
#define assert(condition) do { if (!(condition)) throw std::runtime_error(#condition); } while (false)
#endif

using namespace assets_analytics::event_stage;

namespace {
const Id mc{-1, INT64_MIN, 95000089, std::string(44, 'A'), std::string(44, 'B')};
const Id shard{0, INT64_MIN, 99479309, std::string(44, 'C'), std::string(44, 'D')};
const Id tip{0, INT64_MIN, 99479309, std::string(44, 'C'), std::string(44, 'D')};
const std::string nft_address = "0:bb6c31a9394a76233249d08f27d4356b20bbfea8e20cbae475c3f7c718b590a7";
const std::string dns_address = "0:a2a53de73291d5d419b70f0133ff9c7e0acde948ebfc87cbb74e0c0359cd3cde";

Request request() {
  Request r;
  r.network = "mainnet";
  r.zerostate_root_hash = std::string(44, 'Z');
  r.zerostate_file_hash = std::string(44, 'Y');
  r.mc = mc;
  r.first_included = {mc, shard};
  r.current_tips = {tip};
  r.calc_version = "asset-events-v1";
  r.registry_digest = std::string(64, 'a');
  r.enable_nft = true;
  r.enable_dns = true;
  r.reviewed_nft_items = {nft_address};
  r.reviewed_dns_items = {dns_address};
  r.nft_budget = {2, 1000, 1000, kMaxBatchBytes};
  r.dns_limits = {1, 2, 1000, 10, 1000, 1000, kMaxBatchBytes};
  return r;
}

assets_analytics::nft_events::Result nft() {
  assets_analytics::nft_events::Result n;
  n.mc_anchor = {mc.workchain, mc.shard, mc.seqno, mc.root_hash, mc.file_hash};
  n.examined_transactions = 200;
  return n;
}

assets_analytics::dns::Batch dns() {
  assets_analytics::dns::Batch d;
  d.valid = true;
  return d;
}

Request nft_only() {
  auto r = request();
  r.enable_dns = false;
  r.reviewed_dns_items.clear();
  r.dns_limits = {};
  return r;
}

Request dns_only() {
  auto r = request();
  r.enable_nft = false;
  r.reviewed_nft_items.clear();
  r.nft_budget = {};
  return r;
}

void test_empty_is_not_zero() {
  auto b = reduce(request(), nft(), dns(), {}, {});
  assert(b.valid && b.facts.empty() && b.nft_fact_count == 0 && b.dns_fact_count == 0);
  assert(!b.nft.ready && !b.dns_sold.ready && !b.dns_volume.ready);
  assert(b.nft.reason.find("lifetime") != std::string::npos);
  b = reduce(nft_only(), nft(), std::nullopt, {}, {});
  assert(b.valid && b.nft.status == "unresolved" && b.dns_sold.status == "not_requested");
  assert(render_json(b).find("\"status\":\"not_requested\",\"value\":null") != std::string::npos);
  b = reduce(dns_only(), std::nullopt, dns(), {}, {});
  assert(b.valid && b.nft.status == "not_requested" && b.dns_sold.status == "unresolved");
  assert(!reduce(nft_only(), nft(), dns(), {}, {}).valid);
  assert(!reduce(dns_only(), nft(), dns(), {}, {}).valid);
  assert(!reduce(nft_only(), std::nullopt, std::nullopt, {}, {}).valid);
  auto phantom = nft_only();
  phantom.reviewed_dns_items.push_back(dns_address);
  assert(!reduce(phantom, nft(), std::nullopt, {}, {}).valid);
  phantom = dns_only();
  phantom.nft_budget.max_blocks = 1;
  assert(!reduce(phantom, std::nullopt, dns(), {}, {}).valid);
  phantom = request();
  phantom.enable_nft = phantom.enable_dns = false;
  assert(!reduce(phantom, std::nullopt, std::nullopt, {}, {}).valid);
}

void test_canonical_reviewed_addresses() {
  auto upper = nft_address;
  std::transform(upper.begin(), upper.end(), upper.begin(), [](unsigned char c) {
    return c >= 'a' && c <= 'f' ? static_cast<char>(c - 'a' + 'A') : static_cast<char>(c);
  });
  assert(upper != nft_address);
  assert(assets_analytics::nft_events::canonical_account_address(0, upper.substr(2)) == nft_address);
  assert(assets_analytics::dns::canonical_account_address(0, upper.substr(2)) == nft_address);
  assert(canonical_raw_address(nft_address) && canonical_raw_address(dns_address));
  assert(!canonical_raw_address(upper) && !canonical_raw_address("00:" + nft_address.substr(2)));
  assert(!canonical_raw_address("-:" + nft_address.substr(2)));
  assert(!canonical_raw_address("2147483648:" + nft_address.substr(2)));
  auto r = nft_only();
  r.reviewed_nft_items = {upper};
  assert(!reduce(r, nft(), std::nullopt, {}, {}).valid); // no silently empty reviewed scope
  r = dns_only();
  r.reviewed_dns_items = {upper};
  assert(!reduce(r, std::nullopt, dns(), {}, {}).valid);
}

void test_provenance_and_full_count() {
  auto n = nft();
  std::vector<Fact> facts;
  for (size_t i = 0; i != 80; ++i) {
    assets_analytics::nft_events::Candidate c;
    c.mc_anchor = n.mc_anchor;
    c.source_block = {shard.workchain, shard.shard, shard.seqno, shard.root_hash, shard.file_hash};
    c.account = nft_address;
    c.lt = i + 1;
    c.now = 1789473601;
    c.transaction_hash = std::to_string(i + 1);
    c.state_hash_before = "before";
    c.state_hash_after = "after";
    c.reason = "init_unverified";
    n.candidates.push_back(c);
    Fact f;
    f.family = "nft"; f.signal = "possible_first_initialization";
    f.mc = mc; f.source = shard; f.item = c.account;
    f.tx_hash = c.transaction_hash; f.lt = c.lt; f.now = c.now;
    f.state_before = c.state_hash_before; f.state_after = c.state_hash_after;
    f.status_before = "nonexist"; f.status_after = "nonexist";
    f.reason = "init_unverified"; f.reviewed_item = true;
    facts.push_back(f);
  }
  auto b = reduce(request(), n, dns(), facts, {});
  assert(b.valid && b.facts.size() == 80 && b.nft_fact_count == 80);
  const auto full_json = render_json(b);
  assert(full_json.find("\"fact_count\":80") != std::string::npos);
  size_t occurrences = 0;
  for (size_t pos = 0; (pos = full_json.find("\"signal\":\"possible_first_initialization\"", pos)) !=
                         std::string::npos; ++occurrences, ++pos) {}
  assert(occurrences == 80); // no 64-sample thinning, including the JSON path
  assert(!b.nft.ready && !b.dns_sold.ready);
  auto uppercase = n;
  auto uppercase_facts = facts;
  std::transform(uppercase.candidates[0].account.begin(), uppercase.candidates[0].account.end(),
                 uppercase.candidates[0].account.begin(), [](unsigned char c) {
                   return c >= 'a' && c <= 'f' ? static_cast<char>(c - 'a' + 'A') : static_cast<char>(c);
                 });
  uppercase_facts[0].item = uppercase.candidates[0].account;
  uppercase_facts[0].reviewed_item = false;
  assert(!reduce(request(), uppercase, dns(), uppercase_facts, {}).valid);
  auto bad = facts;
  bad[79].source.file_hash = "wrong";
  auto rejected = reduce(request(), n, dns(), bad, {});
  assert(!rejected.valid && rejected.facts.empty() && rejected.nft_fact_count == 0);
  auto altered = request();
  altered.first_included.pop_back();
  assert(!reduce(altered, n, dns(), facts, {}).valid);
  altered = request();
  altered.nft_budget.max_candidates = 64;
  assert(!reduce(altered, n, dns(), facts, {}).valid);
  n.error = "cap exceeded";
  rejected = reduce(request(), n, dns(), facts, {});
  assert(!rejected.valid && rejected.facts.empty());
  n.error.clear();
  n.candidates[0].reason = std::string(kMaxBatchBytes, 'z');
  facts[0].reason = n.candidates[0].reason;
  rejected = reduce(request(), n, dns(), facts, {});
  assert(!rejected.valid && rejected.facts.empty() && rejected.failure.find("256 KiB") != std::string::npos);
}

void test_dns_transfer_is_not_sale() {
  auto d = dns();
  assets_analytics::dns::Candidate c;
  c.signal = assets_analytics::dns::Signal::secondary_transfer_candidate;
  c.network = "mainnet";
  c.zerostate = request().zerostate_root_hash;
  c.registry_digest = request().registry_digest;
  c.mc_block = {mc.workchain, mc.shard, mc.seqno, mc.root_hash, mc.file_hash};
  c.tx.block = {shard.workchain, shard.shard, shard.seqno, shard.root_hash, shard.file_hash};
  c.tx.item_address = dns_address;
  c.tx.hash = "tx-hash"; c.tx.lt = 100; c.tx.now = 1790346649;
  c.tx.state_hash_before = "before"; c.tx.state_hash_after = "after";
  c.reason = "unresolved";
  assets_analytics::dns::Message msg;
  msg.hash = "message-hash";
  msg.opcode = 0x5fcc3d14;
  c.tx.incoming = msg;
  d.candidates.push_back(c);
  Fact f;
  f.family = "dns"; f.signal = "secondary_transfer_candidate";
  f.mc = mc; f.source = shard; f.item = dns_address;
  f.tx_hash = c.tx.hash; f.lt = c.tx.lt; f.now = c.tx.now;
  f.state_before = c.tx.state_hash_before; f.state_after = c.tx.state_hash_after;
  f.reason = "unresolved"; f.reviewed_item = true;
  f.trigger_message_hash = msg.hash;
  f.messages = {msg};
  auto b = reduce(request(), nft(), d, {}, {f});
  assert(b.valid && b.dns_fact_count == 1 && !b.dns_sold.ready && !b.dns_volume.ready);
  auto forged = d;
  forged.candidates[0].registry_digest = std::string(64, 'b');
  assert(!reduce(request(), nft(), forged, {}, {f}).valid);
  auto altered = f;
  altered.messages[0].hash = "forged-message";
  assert(!reduce(request(), nft(), d, {}, {altered}).valid);
  // Duplicate candidate without a second triggering message must fail whole batch.
  d.candidates.push_back(c);
  b = reduce(request(), nft(), d, {}, {f, f});
  assert(!b.valid && b.facts.empty());

  // Two settlement messages on one tx produce the same signal but two distinct
  // ordinals/triggers. Serialized records must remain distinguishable.
  d.candidates.clear();
  c.signal = assets_analytics::dns::Signal::settlement_candidate;
  assets_analytics::dns::Message payout1, payout2;
  payout1.hash = "payout-1"; payout1.opcode = 0x370fec51;
  payout2.hash = "payout-2"; payout2.opcode = 0x370fec51;
  c.tx.outgoing = {payout1, payout2};
  d.candidates = {c, c};
  f.signal = "settlement_candidate";
  f.signal_ordinal = 0;
  f.trigger_message_hash = payout1.hash;
  f.messages = {msg, payout1, payout2};
  auto second = f;
  second.signal_ordinal = 1;
  second.trigger_message_hash = payout2.hash;
  b = reduce(dns_only(), std::nullopt, d, {}, {f, second});
  assert(b.valid && b.dns_fact_count == 2 && b.facts.size() == 2);
  auto json = render_json(b);
  assert(json.find("\"signal_ordinal\":0,\"trigger_message_hash\":\"payout-1\"") != std::string::npos);
  assert(json.find("\"signal_ordinal\":1,\"trigger_message_hash\":\"payout-2\"") != std::string::npos);
  assert(json.find("\"fact_count\":2") != std::string::npos);
  assert(!reduce(dns_only(), std::nullopt, d, {}, {f, f}).valid);
  d.reason = "malformed raw diff"; d.valid = false;
  b = reduce(dns_only(), std::nullopt, d, {}, {f, second});
  assert(!b.valid && b.facts.empty());
}
} // namespace

int main() {
  test_empty_is_not_zero();
  test_canonical_reviewed_addresses();
  test_provenance_and_full_count();
  test_dns_transfer_is_not_sale();
  std::cout << "AssetEventStage synthetic reducers: PASS\n";
}
