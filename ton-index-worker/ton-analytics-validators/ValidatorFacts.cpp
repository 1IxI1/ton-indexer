#include "ValidatorFacts.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_set>
#include <unordered_map>
#include <utility>
#include <vector>

namespace tonstat::validators {
namespace {

using analytics::validators::stage::Check;
using analytics::validators::stage::Metric;
using analytics::validators::stage::Output;
using analytics::validators::stage::Status;
using analytics::validators::stage::ValidatorFact;

constexpr std::size_t kMaxBytes = 512 * 1024;
constexpr std::size_t kMaxPositions = 4096;

class Json {
 public:
  void add(std::string_view part) {
    if (part.size() > kMaxBytes - text_.size())
      throw std::length_error("validators JSON exceeds 512 KiB");
    text_.append(part.data(), part.size());
  }

  void quote(std::string_view value) {
    static constexpr char hex[] = "0123456789abcdef";
    add("\"");
    for (unsigned char c : value) {
      switch (c) {
        case '\"': add("\\\""); break;
        case '\\': add("\\\\"); break;
        case '\b': add("\\b"); break;
        case '\f': add("\\f"); break;
        case '\n': add("\\n"); break;
        case '\r': add("\\r"); break;
        case '\t': add("\\t"); break;
        default:
          if (c < 0x20 || c >= 0x7f) {
            char escaped[] = {'\\', 'u', '0', '0', hex[c >> 4], hex[c & 15]};
            add(std::string_view(escaped, sizeof(escaped)));
          } else {
            char plain = static_cast<char>(c);
            add(std::string_view(&plain, 1));
          }
      }
    }
    add("\"");
  }

  void key(std::string_view name) { quote(name); add(":"); }
  void str(std::string_view name, std::string_view value) { key(name); quote(value); }
  void optional_hash(std::string_view name, const std::optional<td::Bits256>& hash) {
    key(name);
    if (hash) quote(hash->to_hex()); else add("null");
  }
  void optional_uint(std::string_view name, const std::optional<uint32_t>& value) {
    key(name);
    if (value) add(std::to_string(*value)); else add("null");
  }
  void optional_string(std::string_view name, const std::optional<std::string>& value) {
    key(name);
    if (value) quote(*value); else add("null");
  }
  void number(std::string_view name, uint64_t value) { key(name); add(std::to_string(value)); }
  std::string take() { return std::move(text_); }

 private:
  std::string text_;
};

void require(bool condition, const char* reason) {
  if (!condition) throw std::invalid_argument(reason);
}

// Cheap budget before sorting or expanding escaped strings. The Json append
// limit is still authoritative, including for control-byte expansion.
void charge(std::size_t& budget, std::string_view text) {
  if (text.size() > budget) throw std::length_error("validators input exceeds 512 KiB");
  budget -= text.size();
}

bool decimal(std::string_view value) {
  if (value.empty() || value.size() > 80 || (value.size() > 1 && value.front() == '0')) return false;
  for (char c : value) if (c < '0' || c > '9') return false;
  return true;
}

// t_Grams is VarUInteger16, so an individual on-chain amount is < 2^120.
// A sum across positions may be larger; check only each position here.
bool on_chain_amount(std::string_view value) {
  constexpr std::string_view limit = "1329227995784915872903807060280344576";  // 2^120
  return decimal(value) && (value.size() < limit.size() ||
                            (value.size() == limit.size() && value < limit));
}

bool reviewed_elector(const td::Bits256& hash) {
  const std::string actual = hash.to_hex();
  const std::string_view pinned = analytics::validators::kReviewedElectorCodeHash;
  return actual.size() == pinned.size() &&
         std::equal(actual.begin(), actual.end(), pinned.begin(),
                    [](unsigned char a, unsigned char b) {
                      return a == b || (a >= 'a' && a <= 'f' && a - ('a' - 'A') == b);
                    });
}

std::string add_decimal(std::string left, std::string_view right) {
  std::string result;
  result.reserve(std::max(left.size(), right.size()) + 1);
  int carry = 0;
  for (std::size_t i = 0; i < left.size() || i < right.size() || carry; ++i) {
    int digit = carry;
    if (i < left.size()) digit += left[left.size() - i - 1] - '0';
    if (i < right.size()) digit += right[right.size() - i - 1] - '0';
    result.push_back(static_cast<char>('0' + digit % 10));
    carry = digit / 10;
  }
  std::reverse(result.begin(), result.end());
  require(result.size() <= 80, "validators stake sum exceeds supported decimal range");
  return result;
}

const char* status_name(Status status) {
  switch (status) {
    case Status::ready: return "ready";
    case Status::pending: return "pending";
    case Status::invalid: return "invalid";
  }
  throw std::invalid_argument("unknown validator status");
}

void validate_check(const Check& check, const Output& out, bool previous = false) {
  (void)status_name(check.status);
  if (check.status != Status::ready) {
    require(!check.reason.empty(), "unresolved check needs a reason");
    return;
  }
  require(check.reason.empty(), "ready check has a failure reason");
  require(check.mc_id.is_masterchain() && check.mc_id.is_valid_full() &&
              check.post_state_root != td::Bits256{}, "ready check has no full MC/state binding");
  require(previous ? out.election_boundary &&
                         check.mc_id == out.election_boundary->previous_mc_id &&
                         check.post_state_root == out.election_boundary->previous_post_state_root
                   : check.mc_id == out.mc_id && check.post_state_root == out.post_state_root,
          "ready check references a different MC post-state");
}

void block_id(Json& json, const ton::BlockIdExt& id) {
  json.add("{");
  json.key("workchain"); json.add(std::to_string(id.id.workchain)); json.add(",");
  json.str("shard_hex", [&] {
    constexpr char hex[] = "0123456789abcdef";
    std::string shard(16, '0');
    for (int i = 15; i >= 0; --i) shard[15 - i] = hex[(id.id.shard >> (i * 4)) & 15];
    return shard;
  }()); json.add(",");
  json.number("seqno", id.seqno()); json.add(",");
  json.str("root_hash", id.root_hash.to_hex()); json.add(",");
  json.str("file_hash", id.file_hash.to_hex());
  json.add("}");
}

void check_json(Json& json, const Check& check) {
  json.add("{");
  json.str("status", status_name(check.status)); json.add(",");
  json.str("reason", check.reason); json.add(",");
  json.key("mc_full_id");
  if (check.mc_id.is_valid_full()) block_id(json, check.mc_id); else json.add("null");
  json.add(",");
  json.key("post_state_root_hash");
  if (check.post_state_root != td::Bits256{}) json.quote(check.post_state_root.to_hex());
  else json.add("null");
  json.add("}");
}

enum class Kind { count, selected, accepted, remaining, settlement, apr, apy };

void validate_metric(const Metric& metric, Kind kind) {
  (void)status_name(metric.status);
  if (metric.status != Status::ready) {
    require(!metric.reason.empty() && !metric.value && metric.validators.empty(),
            "unresolved metric has numeric facts or lacks reason");
    return;
  }
  require(kind != Kind::settlement && kind != Kind::apr && kind != Kind::apy,
          "settlement and APR/APY are not observed by this stage");
  require(metric.reason.empty() && metric.value && decimal(*metric.value),
          "ready metric missing canonical exact decimal or has failure reason");
  require(metric.vset_hash && *metric.vset_hash != td::Bits256{} &&
              metric.source_root_hash && *metric.source_root_hash != td::Bits256{},
          "ready metric missing source and validator-set hashes");
  if (kind == Kind::count) {
    require(metric.vset_hash == metric.source_root_hash && !metric.elector_account_hash &&
                !metric.elector_code_hash && !metric.election_id &&
                !metric.validators.empty() &&
                *metric.value == std::to_string(metric.validators.size()),
            "count value/provenance does not match #34 roster");
  } else {
    require(metric.elector_account_hash && *metric.elector_account_hash != td::Bits256{} &&
                metric.elector_code_hash && reviewed_elector(*metric.elector_code_hash),
            "ready stake missing reviewed Elector provenance");
    if (kind == Kind::selected || kind == Kind::accepted)
      require(metric.election_id && *metric.election_id != 0 && !metric.validators.empty(),
              "election stake missing election ID or positions");
  }
  std::unordered_set<std::string> pubkeys;
  std::unordered_set<uint16_t> indices;
  std::string total = "0";
  uint64_t total_weight = 0;
  for (const ValidatorFact& v : metric.validators) {
    require(v.pubkey != td::Bits256{} && pubkeys.insert(v.pubkey.to_hex()).second,
            "duplicate or empty validator pubkey");
    if (v.roster_index)
      require(indices.insert(*v.roster_index).second, "duplicate roster index");
    if (kind == Kind::count) {
      require(v.roster_index && *v.roster_index < metric.validators.size() && v.weight &&
                  *v.weight != 0 && !v.raw_holder && !v.stake_nanoton && !v.banned,
              "count roster lacks canonical index/weight or mixes units");
    } else {
      require(v.raw_holder && *v.raw_holder != td::Bits256{} && v.stake_nanoton &&
                  on_chain_amount(*v.stake_nanoton) && !v.roster_index,
              "stake position missing holder/on-chain amount or has roster index");
      if (kind == Kind::accepted)
        require(!v.weight && !v.banned && v.adnl,
                "accepted candidate has frozen/roster fields or missing ADNL");
      else
        require(v.weight && *v.weight != 0 && v.banned && !v.adnl &&
                    (kind != Kind::selected || !*v.banned),
                "frozen stake lacks weight/ban or carries candidate ADNL");
      total = add_decimal(std::move(total), *v.stake_nanoton);
    }
    if (v.weight) {
      require(*v.weight <= std::numeric_limits<uint64_t>::max() - total_weight,
              "validator weight sum overflow");
      total_weight += *v.weight;
    }
  }
  if (kind == Kind::count)
    require(indices.size() == metric.validators.size() && total_weight != 0,
            "incomplete or zero-weight config #34 roster");
  if (kind != Kind::count)
    require(total == *metric.value, "ready stake does not equal sum of positions");
}

void position_json(Json& json, const ValidatorFact& v) {
  json.add("{");
  json.str("pubkey", v.pubkey.to_hex()); json.add(",");
  json.key("roster_index"); if (v.roster_index) json.add(std::to_string(*v.roster_index)); else json.add("null");
  json.add(","); json.optional_hash("raw_holder", v.raw_holder);
  json.add(","); json.optional_hash("adnl", v.adnl);
  json.add(","); json.key("weight"); if (v.weight) json.add(std::to_string(*v.weight)); else json.add("null");
  json.add(","); json.optional_string("stake_nanoton", v.stake_nanoton);
  json.add(","); json.key("banned");
  if (v.banned) json.add(*v.banned ? "true" : "false"); else json.add("null");
  json.add("}");
}

void metric_json(Json& json, const Metric& metric, Kind kind) {
  json.add("{");
  json.str("status", status_name(metric.status)); json.add(",");
  json.str("reason", metric.reason); json.add(",");
  json.str("unit", kind == Kind::count ? "validators" :
           kind == Kind::apr || kind == Kind::apy ? "not_modelled" : "nanoton"); json.add(",");
  json.key("value_decimal");
  if (metric.status == Status::ready) json.quote(*metric.value); else json.add("null");
  json.add(","); json.optional_hash("vset_hash", metric.vset_hash);
  json.add(","); json.optional_hash("source_root_hash", metric.source_root_hash);
  json.add(","); json.optional_hash("elector_account_hash", metric.elector_account_hash);
  json.add(","); json.optional_hash("elector_code_hash", metric.elector_code_hash);
  json.add(","); json.optional_uint("election_id", metric.election_id);
  json.add(","); json.key("validators"); json.add("[");
  std::vector<const ValidatorFact*> ordered;
  ordered.reserve(metric.validators.size());
  for (const auto& v : metric.validators) ordered.push_back(&v);
  std::sort(ordered.begin(), ordered.end(), [](const auto* a, const auto* b) {
    if (a->roster_index && b->roster_index && *a->roster_index != *b->roster_index)
      return *a->roster_index < *b->roster_index;
    return a->pubkey.to_hex() < b->pubkey.to_hex();
  });
  for (std::size_t i = 0; i < ordered.size(); ++i) {
    if (i) json.add(",");
    position_json(json, *ordered[i]);
  }
  json.add("]}");
}

void budget_input(const Output& out) {
  std::size_t budget = kMaxBytes;
  for (const auto& text : {&out.calc_version, &out.scope, &out.snapshot_decoder_version,
                           &out.network_zerostate, &out.network_zerostate_file_hash}) charge(budget, *text);
  const auto check = [&](const Check& c) { charge(budget, c.reason); };
  check(out.anchor.raw_block_file_hash);
  check(out.anchor.header_and_predecessor);
  check(out.anchor.state_update);
  if (out.election_boundary) {
    check(out.election_boundary->first_post_election);
    check(out.election_boundary->previous_state_and_config36);
  }
  for (const Metric* m : {&out.count, &out.selected_initial, &out.accepted,
                          &out.frozen_remaining, &out.settlement, &out.apr, &out.apy}) {
    charge(budget, m->reason);
    if (m->value) charge(budget, *m->value);
    if (m->validators.size() > kMaxPositions)
      throw std::length_error("validators metric exceeds position limit");
    for (const auto& v : m->validators) if (v.stake_nanoton) charge(budget, *v.stake_nanoton);
  }
}

}  // namespace

std::string render_batch_json(const Output& out) {
  budget_input(out);
  const auto version = [](std::string_view value) {
    if (value.empty() || value.size() > 128) return false;
    for (unsigned char c : value)
      if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '/' || c == '+'))
        return false;
    return true;
  };
  require(version(out.calc_version) && version(out.snapshot_decoder_version) &&
              out.scope == "single_attested_mc_post_state/producer_only" &&
              out.network_zerostate.size() == 64 && out.network_zerostate_file_hash.size() == 64 &&
              out.mc_id.is_masterchain() && out.mc_id.is_valid_full() &&
              out.post_state_root != td::Bits256{}, "validators batch missing full network/MC/state provenance");
  const auto valid_hash = [](const std::string& value) {
    if (value == std::string(64, '0')) return false;
    for (unsigned char c : value)
      if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) return false;
    return true;
  };
  require(valid_hash(out.network_zerostate) && valid_hash(out.network_zerostate_file_hash),
          "invalid zerostate root/file hash");
  for (const Check* c : {&out.anchor.raw_block_file_hash, &out.anchor.header_and_predecessor,
                         &out.anchor.state_update}) validate_check(*c, out);
  if (out.election_boundary) {
    validate_check(out.election_boundary->first_post_election, out);
    validate_check(out.election_boundary->previous_state_and_config36, out, true);
    if (out.election_boundary->previous_state_and_config36.status == Status::ready)
      require(out.election_boundary->previous_mc_id.is_masterchain() &&
                  out.election_boundary->previous_mc_id.is_valid_full() &&
                  out.election_boundary->previous_post_state_root != td::Bits256{},
              "ready election boundary missing previous MC post-state");
    if (out.election_boundary->first_post_election.status == Status::ready &&
        out.election_boundary->previous_state_and_config36.status == Status::ready)
      require(out.election_boundary->election_id != 0 &&
                  out.election_boundary->selected_vset_hash != td::Bits256{} &&
                  out.election_boundary->previous_mc_id.seqno() < out.mc_id.seqno() &&
                  out.election_boundary->previous_mc_id.seqno() + 1 == out.mc_id.seqno() &&
                  out.election_boundary->previous_post_state_root != out.post_state_root &&
                  (!out.election_boundary->previous_config36_hash ||
                   *out.election_boundary->previous_config36_hash !=
                       out.election_boundary->selected_vset_hash),
              "contradictory ready election boundary");
  }
  const bool anchored = out.anchor.raw_block_file_hash.status == Status::ready &&
                        out.anchor.header_and_predecessor.status == Status::ready &&
                        out.anchor.state_update.status == Status::ready;
  for (const Metric* m : {&out.count, &out.selected_initial, &out.accepted,
                          &out.frozen_remaining, &out.settlement, &out.apr, &out.apy})
    if (m->status == Status::ready) require(anchored, "ready metric with unresolved anchor");
  if (out.selected_initial.status == Status::ready) {
    require(out.election_boundary &&
                out.election_boundary->first_post_election.status == Status::ready &&
                out.election_boundary->previous_state_and_config36.status == Status::ready &&
                out.selected_initial.vset_hash == out.election_boundary->selected_vset_hash &&
                out.selected_initial.election_id == out.election_boundary->election_id,
            "selected stake has no matching verified election boundary");
  }
  if (out.frozen_remaining.status == Status::ready)
    require(out.count.status == Status::ready &&
                out.frozen_remaining.vset_hash == out.count.vset_hash,
            "frozen remaining lacks matching ready config #34 roster");
  for (const auto& pair : {
           std::pair<const Metric*, Kind>{&out.count, Kind::count},
           {&out.selected_initial, Kind::selected}, {&out.accepted, Kind::accepted},
           {&out.frozen_remaining, Kind::remaining}, {&out.settlement, Kind::settlement},
           {&out.apr, Kind::apr}, {&out.apy, Kind::apy}})
    validate_metric(*pair.first, pair.second);
  if (out.frozen_remaining.status == Status::ready) {
    require(out.frozen_remaining.validators.size() == out.count.validators.size(),
            "frozen remaining does not cover the entire #34 roster");
    std::unordered_map<std::string, uint64_t> roster;
    for (const auto& member : out.count.validators)
      roster.emplace(member.pubkey.to_hex(), *member.weight);
    for (const auto& member : out.frozen_remaining.validators) {
      const auto it = roster.find(member.pubkey.to_hex());
      require(it != roster.end() && it->second == *member.weight,
              "frozen remaining pubkey/weight differs from #34 roster");
    }
  }
  Json json;
  json.add("{");
  json.str("dataset", "validators"); json.add(",");
  json.str("scope", out.scope); json.add(",");
  json.str("calc_version", out.calc_version); json.add(",");
  json.str("snapshot_decoder_version", out.snapshot_decoder_version); json.add(",");
  json.str("zerostate_root_hash", out.network_zerostate); json.add(",");
  json.str("zerostate_file_hash", out.network_zerostate_file_hash); json.add(",");
  json.key("mc_full_id"); block_id(json, out.mc_id); json.add(",");
  json.str("mc_post_state_root_hash", out.post_state_root.to_hex()); json.add(",");
  json.number("mc_gen_utime", out.gen_utime); json.add(",");
  json.key("anchor"); json.add("{");
  json.key("raw_block_file_hash"); check_json(json, out.anchor.raw_block_file_hash); json.add(",");
  json.key("header_and_predecessor"); check_json(json, out.anchor.header_and_predecessor); json.add(",");
  json.key("state_update"); check_json(json, out.anchor.state_update); json.add("},");
  json.key("election_boundary");
  if (!out.election_boundary) json.add("null");
  else {
    const auto& e = *out.election_boundary;
    json.add("{");
    json.key("first_post_election"); check_json(json, e.first_post_election); json.add(",");
    json.key("previous_state_and_config36"); check_json(json, e.previous_state_and_config36); json.add(",");
    json.key("previous_mc_full_id");
    if (e.previous_mc_id.is_valid_full()) block_id(json, e.previous_mc_id); else json.add("null");
    json.add(",");
    json.key("previous_post_state_root_hash");
    if (e.previous_post_state_root != td::Bits256{}) json.quote(e.previous_post_state_root.to_hex());
    else json.add("null");
    json.add(",");
    json.optional_hash("previous_config36_hash", e.previous_config36_hash); json.add(",");
    json.number("election_id", e.election_id); json.add(",");
    json.str("selected_vset_hash", e.selected_vset_hash.to_hex()); json.add("}");
  }
  json.add(",");
  json.key("metrics"); json.add("{");
  json.key("count"); metric_json(json, out.count, Kind::count); json.add(",");
  json.key("selected_initial"); metric_json(json, out.selected_initial, Kind::selected); json.add(",");
  json.key("accepted"); metric_json(json, out.accepted, Kind::accepted); json.add(",");
  json.key("frozen_remaining"); metric_json(json, out.frozen_remaining, Kind::remaining); json.add(",");
  json.key("settlement"); metric_json(json, out.settlement, Kind::settlement); json.add(",");
  json.key("apr"); metric_json(json, out.apr, Kind::apr); json.add(",");
  json.key("apy"); metric_json(json, out.apy, Kind::apy); json.add("},");
  json.add("\"producer_only\":true,\"writer_committed\":false,\"publication_ready\":false,");
  json.add("\"daily_complete\":false,\"readiness_basis\":\"caller_attested_not_authenticated\"}");
  return json.take();
}

}  // namespace tonstat::validators
