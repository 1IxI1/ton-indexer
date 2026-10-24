#include "ValidatorFacts.h"

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <string>
#include <utility>

using analytics::validators::stage::Check;
using analytics::validators::stage::Metric;
using analytics::validators::stage::Output;
using analytics::validators::stage::Status;
using analytics::validators::stage::ValidatorFact;
using tonstat::validators::render_batch_json;

namespace {

td::Bits256 hash(unsigned char byte) {
  td::Bits256 result{};
  result.as_array().fill(byte);
  return result;
}

td::Bits256 reviewed_elector_hash() {
  constexpr char hex[] = "6217F872C99FAFCB870F2C11A362F59339BE95095F70D00B9CFF2F6DCD69D3DD";
  const auto nibble = [](char c) -> unsigned char {
    return static_cast<unsigned char>(c <= '9' ? c - '0' : c - 'A' + 10);
  };
  td::Bits256 result{};
  for (std::size_t i = 0; i < result.as_array().size(); ++i)
    result.as_array()[i] = static_cast<unsigned char>((nibble(hex[i * 2]) << 4) | nibble(hex[i * 2 + 1]));
  return result;
}

ton::BlockIdExt mc(uint32_t seq) { return {-1, uint64_t{1} << 63, seq, hash(1), hash(2)}; }

Check bound(const Output& out) {
  Check check;
  check.status = Status::ready;
  check.reason.clear();
  check.mc_id = out.mc_id;
  check.post_state_root = out.post_state_root;
  return check;
}

Output fixture() {
  Output out;
  out.network_zerostate = std::string(64, 'a');
  out.network_zerostate_file_hash = std::string(64, 'b');
  out.mc_id = mc(23);
  out.post_state_root = hash(3);
  out.gen_utime = 1234567;
  out.anchor.raw_block_file_hash = bound(out);
  out.anchor.header_and_predecessor = bound(out);
  out.anchor.state_update = bound(out);
  out.count.status = Status::ready;
  out.count.reason.clear();
  out.count.value = "2";
  out.count.vset_hash = hash(4);
  out.count.source_root_hash = hash(4);
  out.count.validators.push_back({hash(11), std::nullopt, hash(21), 1, 100, std::nullopt, std::nullopt});
  out.count.validators.push_back({hash(10), std::nullopt, std::nullopt, 0, 50, std::nullopt, std::nullopt});
  out.selected_initial.reason = "first_post_election_config_36_not_proven";
  out.accepted.status = Status::invalid;
  out.accepted.reason = "election_component_invalid";
  out.frozen_remaining.reason = "elector_code_not_reviewed";
  out.settlement.reason = "isolated_settlement_not_verified";
  out.apr.reason = "settlement_not_verified";
  out.apy.reason = "settlement_not_verified";
  return out;
}

bool has(const std::string& s, const std::string& part) { return s.find(part) != std::string::npos; }

void invalid(const Output& out) {
  try { (void)render_batch_json(out); }
  catch (const std::invalid_argument&) { return; }
  assert(false && "expected invalid_argument");
}

void oversized(const Output& out) {
  try { (void)render_batch_json(out); }
  catch (const std::length_error&) { return; }
  assert(false && "expected length_error");
}

}  // namespace

int main() {
  auto a = fixture();
  a.producer_only = false; a.writer_committed = true; a.publication = true;
  std::string json = render_batch_json(a);
  assert(!json.empty() && json.front() == '{' && json.back() == '}');
  assert(json.find('\n') == std::string::npos);
  assert(has(json, "\"workchain\":-1"));
  assert(has(json, "\"root_hash\":\"" + hash(1).to_hex() + "\""));
  assert(has(json, "\"file_hash\":\"" + hash(2).to_hex() + "\""));
  assert(has(json, "\"zerostate_file_hash\":\"" + std::string(64, 'b') + "\""));
  assert(has(json, "\"mc_post_state_root_hash\":\"" + hash(3).to_hex() + "\""));
  assert(has(json, "\"count\":{\"status\":\"ready\",\"reason\":\"\",\"unit\":\"validators\",\"value_decimal\":\"2\""));
  assert(has(json, "\"selected_initial\":{\"status\":\"pending\",\"reason\":\"first_post_election_config_36_not_proven\",\"unit\":\"nanoton\",\"value_decimal\":null"));
  assert(has(json, "\"accepted\":{\"status\":\"invalid\",\"reason\":\"election_component_invalid\",\"unit\":\"nanoton\",\"value_decimal\":null"));
  assert(has(json, "\"writer_committed\":false"));
  assert(has(json, "\"publication_ready\":false"));
  assert(has(json, "\"daily_complete\":false"));
  assert(has(json, "\"producer_only\":true"));
  assert(has(json, "\"readiness_basis\":\"caller_attested_not_authenticated\""));
  assert(json.find(hash(10).to_hex()) < json.find(hash(11).to_hex())); // original roster index

  a.count.value = "0";
  a.count.validators.clear();
  invalid(a); // validated config #34 cannot have an empty validator set
  a.count.status = Status::pending;
  a.count.reason = "not_verified";
  a.count.value.reset();
  json = render_batch_json(a);
  assert(has(json, "\"count\":{\"status\":\"pending\",\"reason\":\"not_verified\",\"unit\":\"validators\",\"value_decimal\":null"));

  a = fixture();
  a.apr.reason = "quote \" slash \\ line\n tab\t byte\x01";
  a.selected_initial.reason = std::string("bad\xff", 4);
  json = render_batch_json(a);
  assert(has(json, "\"reason\":\"quote \\\" slash \\\\ line\\n tab\\t byte\\u0001\""));
  assert(has(json, "\"reason\":\"bad\\u00ff\""));

  a = fixture();
  for (unsigned i = 2; i < 400; ++i) {
    td::Bits256 key{};
    key.as_array()[30] = static_cast<unsigned char>(i >> 8);
    key.as_array()[31] = static_cast<unsigned char>(i);
    a.count.validators.push_back({key, std::nullopt, std::nullopt,
                                  static_cast<uint16_t>(i), uint64_t{1}, std::nullopt, std::nullopt});
  }
  a.count.value = "400";
  json = render_batch_json(a);
  assert(json.size() < 512 * 1024);
  auto shuffled = a;
  std::reverse(shuffled.count.validators.begin(), shuffled.count.validators.end());
  assert(render_batch_json(shuffled) == json);

  a = fixture();
  a.count.validators.push_back(a.count.validators.front());
  a.count.value = "3";
  invalid(a);
  a = fixture();
  a.count.validators.back().roster_index = a.count.validators.front().roster_index;
  invalid(a);
  a = fixture();
  a.count.validators.back().roster_index = 2; // gap: 0, 2 rather than 0, 1
  invalid(a);
  a = fixture();
  a.count.validators.front().weight = 0;
  invalid(a);
  a = fixture();
  a.count.validators.front().weight = std::numeric_limits<uint64_t>::max();
  invalid(a); // sum of two nonzero weights overflows uint64
  a = fixture();
  a.count.value = "01";
  invalid(a);
  a = fixture();
  a.count.value.reset();
  invalid(a);
  a = fixture();
  a.count.validators.front().stake_nanoton = "0";
  invalid(a); // count and nanoTON position units cannot be mixed
  a = fixture();
  a.count.source_root_hash.reset();
  invalid(a);
  a = fixture();
  a.accepted.value = "0";
  invalid(a);
  a = fixture();
  a.apy.status = Status::ready; a.apy.value = "0"; a.apy.reason.clear();
  invalid(a); // no stage-observed APY
  a = fixture();
  a.anchor.state_update.status = Status::pending;
  a.anchor.state_update.reason = "missing_state_update";
  invalid(a); // ready count without full anchor
  a = fixture();
  a.anchor.raw_block_file_hash.mc_id = mc(24);
  invalid(a);
  a = fixture();
  a.network_zerostate_file_hash.clear();
  invalid(a);

  a = fixture();
  a.count.status = Status::pending; a.count.reason = "not_ready";
  a.count.value.reset(); a.count.validators.clear();
  a.frozen_remaining.status = Status::ready;
  a.frozen_remaining.reason.clear();
  a.frozen_remaining.value = "5";
  a.frozen_remaining.vset_hash = hash(4);
  a.frozen_remaining.source_root_hash = hash(5);
  a.frozen_remaining.elector_account_hash = hash(6);
  a.frozen_remaining.elector_code_hash = reviewed_elector_hash();
  a.frozen_remaining.validators.push_back({hash(11), hash(9), std::nullopt, std::nullopt, 100, "5", false});
  a.frozen_remaining.validators.push_back({hash(10), hash(19), std::nullopt, std::nullopt, 50, "0", true});
  invalid(a); // remaining depends on #34
  a.count = fixture().count;
  json = render_batch_json(a);
  assert(has(json, "\"frozen_remaining\":{\"status\":\"ready\",\"reason\":\"\",\"unit\":\"nanoton\",\"value_decimal\":\"5\""));
  assert(has(json, "\"stake_nanoton\":\"5\",\"banned\":false"));
  a.frozen_remaining.validators.back().weight = 49;
  invalid(a); // a ready remaining position must match its #34 member weight
  a.frozen_remaining.validators.back().weight = 50;
  a.frozen_remaining.value = "0";
  invalid(a); // aggregate doesn't match positions
  a.frozen_remaining.validators.front().stake_nanoton = "0";
  json = render_batch_json(a); // two explicitly verified zero positions, not unknown
  assert(has(json, "\"frozen_remaining\":{\"status\":\"ready\",\"reason\":\"\",\"unit\":\"nanoton\",\"value_decimal\":\"0\""));
  assert(has(json, "\"stake_nanoton\":\"0\",\"banned\":true"));
  a.frozen_remaining.elector_code_hash = hash(7);
  invalid(a);

  a = fixture();
  a.election_boundary.emplace();
  json = render_batch_json(a);
  assert(has(json, "\"previous_mc_full_id\":null"));
  assert(has(json, "\"previous_post_state_root_hash\":null"));
  a.election_boundary->previous_mc_id = mc(22);
  a.election_boundary->previous_post_state_root = hash(30);
  a.election_boundary->first_post_election = bound(a);
  a.election_boundary->previous_state_and_config36.status = Status::ready;
  a.election_boundary->previous_state_and_config36.reason.clear();
  a.election_boundary->previous_state_and_config36.mc_id = mc(22);
  a.election_boundary->previous_state_and_config36.post_state_root = hash(30);
  a.election_boundary->election_id = 777;
  a.election_boundary->selected_vset_hash = hash(31);
  a.selected_initial.status = Status::ready; a.selected_initial.reason.clear();
  a.selected_initial.value = "125";
  a.selected_initial.vset_hash = hash(31);
  a.selected_initial.source_root_hash = hash(32);
  a.selected_initial.elector_account_hash = hash(33);
  a.selected_initial.elector_code_hash = reviewed_elector_hash();
  a.selected_initial.election_id = 777;
  a.selected_initial.validators.push_back({hash(35), hash(36), std::nullopt, std::nullopt,
                                           10, "125", false});
  json = render_batch_json(a);
  assert(has(json, "\"selected_initial\":{\"status\":\"ready\",\"reason\":\"\",\"unit\":\"nanoton\",\"value_decimal\":\"125\""));
  assert(has(json, "\"previous_config36_hash\":null"));
  a.selected_initial.validators.front().banned = true;
  invalid(a); // initial winners are unbanned in this reviewed Elector version
  a.selected_initial.validators.front().banned = false;
  a.selected_initial.elector_code_hash = hash(34);
  invalid(a);
  a.selected_initial.elector_code_hash = reviewed_elector_hash();
  a.selected_initial.election_id = 778;
  invalid(a);

  a = fixture();
  a.accepted.status = Status::ready; a.accepted.reason.clear();
  a.accepted.value = "12345678901234567890123456789012345";
  a.accepted.vset_hash = hash(40);
  a.accepted.source_root_hash = hash(41);
  a.accepted.elector_account_hash = hash(42);
  a.accepted.elector_code_hash = reviewed_elector_hash();
  a.accepted.election_id = 777;
  a.accepted.validators.push_back({hash(44), hash(45), hash(46), std::nullopt,
                                   std::nullopt, *a.accepted.value, std::nullopt});
  json = render_batch_json(a);
  assert(has(json, "\"accepted\":{\"status\":\"ready\",\"reason\":\"\",\"unit\":\"nanoton\",\"value_decimal\":\"12345678901234567890123456789012345\""));
  assert(has(json, "\"raw_holder\":\"" + hash(45).to_hex() + "\""));
  assert(has(json, "\"adnl\":\"" + hash(46).to_hex() + "\""));
  a.accepted.validators.front().stake_nanoton = "1329227995784915872903807060280344576"; // 2^120
  a.accepted.value = *a.accepted.validators.front().stake_nanoton;
  invalid(a);
  a.accepted.validators.front().stake_nanoton = "1329227995784915872903807060280344575"; // < 2^120
  a.accepted.value = *a.accepted.validators.front().stake_nanoton;
  assert(has(render_batch_json(a), "\"stake_nanoton\":\"1329227995784915872903807060280344575\""));
  a.accepted.elector_code_hash = hash(43);
  invalid(a);
  a.accepted.elector_code_hash = reviewed_elector_hash();
  a.accepted.validators.front().adnl.reset();
  invalid(a);

  a = fixture();
  a.apy.reason = std::string(120000, '\x01');
  oversized(a); // raw input fits; escaped JSON does not
  a = fixture();
  a.apy.reason = std::string(600000, 'z');
  oversized(a); // raw input budget
}
