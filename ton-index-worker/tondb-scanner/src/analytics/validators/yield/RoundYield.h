#pragma once

// Pure settlement mathematics. The caller must verify historical MC states, the
// #34 / past-election hash match, frozen-dictionary completeness, code semantics,
// and isolation of the Elector credits transition. No DB/TON reader is used here.

#include <boost/multiprecision/cpp_dec_float.hpp>
#include <boost/multiprecision/cpp_int.hpp>
#include <boost/version.hpp>

#include <algorithm>
#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

namespace tonstat::validators::yield {

using Nano = boost::multiprecision::cpp_int;
constexpr std::uint64_t kYearSeconds = 365ULL * 86400;
constexpr const char* kAprRule = "selection-to-unfreeze/365d/exact-rational/percent-6dp-half-away-v1";
constexpr const char* kApyRule = "model-full-reinvestment/decimal100/percent-6dp-half-away-v1/boost-"
                                 BOOST_LIB_VERSION;
// Raw account code cell hash observed for the reviewed unfreeze implementation.
// Adding support for another version requires independently reviewing its
// reward, fine, banned, and credits semantics; a caller flag is not enough.
constexpr const char* kStudiedElectorCodeHash =
    "6217f872c99fafcb870f2c11a362f59339be95095f70d00b9cff2f6dcd69d3dd";
constexpr std::uint64_t kFullMasterchainShard = 0x8000000000000000ULL;

enum class ElectorRule {
  // The studied code's selected frozen entries have banned=false. Do not
  // silently project its observation onto other historical code versions.
  studied_unfreeze_v1,
  // Placeholder for a FUTURE independently reviewed, hash-pinned version.
  // Currently unsupported; a caller assertion cannot enable it.
  unreviewed_ban_aware_unfreeze,
};

struct McAnchor {
  std::int32_t workchain = 0;
  std::uint64_t shard = 0;
  std::uint64_t seqno = 0;
  std::string root_hash;
  std::string file_hash;
  std::string post_state_root_hash;
  std::uint64_t gen_utime = 0;
  std::string elector_code_hash;  // account code in THIS MC post-state
};

struct Provenance {
  std::string network;  // nonzero 256-bit zerostate ROOT hash, never a display name
  McAnchor selection;
  McAnchor pre_unfreeze;
  McAnchor post_unfreeze;
  std::string elector_code_hash;
  // Asserted by the native reader after checking complete MC identities and
  // post-state roots. Shape/order checks below do NOT verify a block proof.
  bool mc_block_ids_and_states_verified = false;
  bool election_vset_and_membership_verified = false;
  bool selected_snapshot_complete = false;
  bool pre_unfreeze_snapshot_complete = false;
  bool isolated_unfreeze_transition_verified = false;
  bool complete_holder_credit_changes_verified = false;
  bool elector_code_semantics_verified = false;
  bool actual_timestamps_verified = false;
};

struct PositionInput {
  std::string pubkey;  // raw 256-bit key, 64 hex chars
  std::string holder;  // raw 256-bit Elector credits key; do not attribute to an LST
  std::optional<Nano> selected_principal;  // first selected frozen snapshot, P
  std::optional<Nano> pre_unfreeze_stake;  // immediately before unfreeze, S
  std::optional<bool> banned;
  std::uint64_t selected_at = 0;  // actual selection MC time
  std::uint64_t unfrozen_at = 0;  // actual unfreeze MC time
};

struct HolderCredits {
  std::string holder;
  std::optional<Nano> before;
  std::optional<Nano> after;
};

struct RoundInput {
  Provenance proof;
  ElectorRule rule = ElectorRule::studied_unfreeze_v1;
  std::uint64_t election_id = 0;
  std::string vset_hash;
  std::optional<std::size_t> selected_positions;
  std::optional<Nano> selected_total;
  std::optional<Nano> total_stake_before_unfreeze;
  std::optional<Nano> bonuses_total;
  std::vector<PositionInput> positions;
  // Include EVERY changed holder, and each position's holder even if delta=0.
  std::vector<HolderCredits> credits;
};

struct YieldRate {
  Nano annual_numerator;    // exact APR fraction of 1: income * YEAR
  Nano annual_denominator;  // stake * actual seconds (group: sum P_i * dt_i)
  std::string apr_percent_6;  // fixed six decimals, half away from zero
  std::string model_apy_percent_6;  // hypothetical, NOT observed holder APY
};

struct PositionResult {
  std::string network;
  std::uint64_t election_id;
  std::string vset_hash;
  std::string pubkey;
  std::string holder;
  Nano principal;        // P
  Nano pre_unfreeze;     // S
  Nano returned;         // Q; banned semantics unsupported in this version
  Nano fine;             // P-S
  Nano uncredited_stake; // S-Q (zero for the supported non-banned code)
  Nano loss;             // P-Q
  Nano bonus;            // B, floor for each non-banned position
  std::uint64_t duration;
  YieldRate gross;
  YieldRate net;
};

struct RoundResult {
  std::string network;
  std::uint64_t election_id;
  std::string vset_hash;
  ElectorRule elector_rule;
  std::string elector_code_hash;
  // Copy of the checked source IDs and declared completeness/evidence flags;
  // each child position is interpreted with THIS parent proof, never alone.
  Provenance proof;
  std::vector<PositionResult> positions;
  Nano principal = 0;
  Nano pre_unfreeze = 0;
  Nano returned = 0;
  Nano fine = 0;
  Nano uncredited_stake = 0;
  Nano loss = 0;
  Nano awarded_bonus = 0;
  Nano undistributed_bonus = 0;  // floor remainder (ban allocation unsupported)
  Nano stake_seconds = 0;
  YieldRate gross;
  YieldRate net;
};

namespace detail {

inline void require(bool ok, const char* why) {
  if (!ok) throw std::invalid_argument(why);
}

inline bool hex256(const std::string& s) {
  return s.size() == 64 && std::all_of(s.begin(), s.end(), [](char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
  });
}

inline std::string normalized_hex(const std::string& s) {
  require(hex256(s), "missing or malformed 256-bit identity/hash");
  std::string out = s;
  std::transform(out.begin(), out.end(), out.begin(), [](char c) {
    return c >= 'A' && c <= 'F' ? static_cast<char>(c - 'A' + 'a') : c;
  });
  return out;
}

inline Nano amount(const std::optional<Nano>& x, bool positive = false) {
  require(x.has_value(), "missing monetary fact (not zero)");
  // TVM coins/VarUInteger16 hold at most 120 bits; do not accept negatives.
  require(*x >= 0 && *x < (Nano(1) << 120) && (!positive || *x > 0),
          "out-of-range monetary fact");
  return *x;
}

inline std::uint64_t duration(std::uint64_t start, std::uint64_t end) {
  // On-chain gen_utime is uint32. Zero and backwards/equal timestamps are not
  // a measured lock period; do not substitute scheduled config times.
  require(start > 0 && end > start && end <= UINT32_MAX, "invalid actual lock timestamps");
  return end - start;
}

inline McAnchor checked_anchor(McAnchor a) {
  require(a.workchain == -1 && a.shard == kFullMasterchainShard && a.seqno > 0 &&
              a.seqno <= UINT32_MAX, "invalid full masterchain block ID");
  a.root_hash = normalized_hex(a.root_hash);
  a.file_hash = normalized_hex(a.file_hash);
  a.post_state_root_hash = normalized_hex(a.post_state_root_hash);
  a.elector_code_hash = normalized_hex(a.elector_code_hash);
  require(a.root_hash != std::string(64, '0') && a.file_hash != std::string(64, '0') &&
              a.post_state_root_hash != std::string(64, '0'), "zero block/state hash");
  require(a.gen_utime > 0 && a.gen_utime <= UINT32_MAX, "invalid MC gen_utime");
  return a;
}

inline std::string percent_6(const Nano& numerator, const Nano& denominator) {
  require(denominator > 0, "zero rate denominator");
  bool negative = numerator < 0;
  Nano scaled = (negative ? -numerator : numerator) * 100000000;
  Nano rounded = (scaled * 2 + denominator) / (denominator * 2);
  Nano integer = rounded / 1000000;
  std::string fraction = (rounded % 1000000).convert_to<std::string>();
  fraction.insert(0, 6 - fraction.size(), '0');
  return std::string(negative && rounded != 0 ? "-" : "") + integer.convert_to<std::string>() +
         "." + fraction;
}

using Decimal = boost::multiprecision::cpp_dec_float_100;

inline Decimal as_decimal(const Nano& value) { return Decimal(value.convert_to<std::string>()); }

inline std::string model_apy_6(const Nano& income, const Nano& principal,
                               const Nano& stake_seconds) {
  // Effective group lock duration = Σ(P_i*dt_i)/ΣP_i. For individuals it is
  // simply dt_i. This is a MODEL of identical repeated periods, not a cash flow.
  require(principal > 0 && stake_seconds > 0, "zero model denominator");
  require(principal + income >= 0, "negative reinvestment base");
  Decimal base = as_decimal(principal + income) / as_decimal(principal);
  Decimal periods = Decimal(kYearSeconds) * as_decimal(principal) / as_decimal(stake_seconds);
  // A one-second period with a huge return can exceed any sensible finite
  // decimal output. Fail, never emit infinity or a misleading clipped value.
  require(base <= 1 || log10(base) * periods < 1000,
          "model APY exceeds supported 1000-digit display range");
  Decimal percent = (base == 0 ? Decimal(0) : pow(base, periods)) * 100 - 100;
  Decimal scaled = abs(percent) * 1000000;
  // Truncate only at the final six-decimal display boundary.
  Nano rounded = floor(scaled + Decimal("0.5")).convert_to<Nano>();
  Nano integer = rounded / 1000000;
  std::string fraction = (rounded % 1000000).convert_to<std::string>();
  fraction.insert(0, 6 - fraction.size(), '0');
  return std::string(percent < 0 && rounded != 0 ? "-" : "") +
         integer.convert_to<std::string>() + "." + fraction;
}

inline YieldRate rate(const Nano& income, const Nano& principal, const Nano& stake_seconds) {
  require(principal > 0 && stake_seconds > 0, "zero annualization denominator");
  Nano annual = income * kYearSeconds;
  return {annual, stake_seconds, percent_6(annual, stake_seconds),
          model_apy_6(income, principal, stake_seconds)};
}

}  // namespace detail

// Throws invalid_argument on ANY missing, contradictory or unverified fact.
// Returned output is all-or-nothing; a partial round must remain unpublished.
inline RoundResult settle_round(const RoundInput& in) {
  using detail::require;
  const auto& p = in.proof;
  require(p.mc_block_ids_and_states_verified &&
              p.election_vset_and_membership_verified &&
              p.selected_snapshot_complete && p.pre_unfreeze_snapshot_complete &&
              p.isolated_unfreeze_transition_verified && p.complete_holder_credit_changes_verified &&
              p.elector_code_semantics_verified && p.actual_timestamps_verified,
          "incomplete historical provenance");
  auto network = detail::normalized_hex(p.network);
  require(network != std::string(64, '0'), "zero network zerostate root hash");
  auto selection = detail::checked_anchor(p.selection);
  auto pre = detail::checked_anchor(p.pre_unfreeze);
  auto post = detail::checked_anchor(p.post_unfreeze);
  require(selection.seqno <= pre.seqno && pre.seqno < UINT32_MAX &&
              pre.seqno + 1 == post.seqno, "unfreeze anchors are not adjacent MC blocks");
  // Consecutive MC blocks can share gen_utime (observed at 99187658->59).
  // Selection must still precede the credited unfreeze in actual time.
  require(selection.gen_utime <= pre.gen_utime && pre.gen_utime <= post.gen_utime &&
              selection.gen_utime < post.gen_utime, "MC anchor timestamps are not ordered");
  if (selection.seqno == pre.seqno) {
    require(selection.root_hash == pre.root_hash && selection.file_hash == pre.file_hash &&
                selection.post_state_root_hash == pre.post_state_root_hash &&
                selection.gen_utime == pre.gen_utime,
            "same MC block ID has conflicting selection/pre state");
  }
  auto elector_code_hash = detail::normalized_hex(p.elector_code_hash);
  require(pre.post_state_root_hash != post.post_state_root_hash &&
              selection.post_state_root_hash != post.post_state_root_hash &&
              pre.root_hash != post.root_hash && pre.file_hash != post.file_hash,
          "no proven unfreeze state change");
  require(in.election_id > 0 && in.election_id <= UINT32_MAX, "invalid election ID");
  auto vset = detail::normalized_hex(in.vset_hash);
  require(in.rule == ElectorRule::studied_unfreeze_v1 &&
              elector_code_hash == kStudiedElectorCodeHash &&
              selection.elector_code_hash == elector_code_hash &&
              pre.elector_code_hash == elector_code_hash &&
              post.elector_code_hash == elector_code_hash,
          "unsupported or unreviewed Elector code/ban semantics");
  require(in.selected_positions && *in.selected_positions > 0 &&
              *in.selected_positions == in.positions.size(), "incomplete selected set");
  Nano original = detail::amount(in.selected_total, true);
  Nano total = detail::amount(in.total_stake_before_unfreeze);
  Nano bonuses = detail::amount(in.bonuses_total);
  require(bonuses == 0 || total > 0, "bonus allocation with zero frozen stake");

  RoundResult out;
  out.network = network;
  out.election_id = in.election_id;
  out.vset_hash = vset;
  out.elector_rule = in.rule;
  out.elector_code_hash = elector_code_hash;
  out.proof = p;
  out.proof.network = network;
  out.proof.selection = selection;
  out.proof.pre_unfreeze = pre;
  out.proof.post_unfreeze = post;
  out.proof.elector_code_hash = elector_code_hash;
  std::set<std::string> keys;
  std::map<std::string, Nano> expected_credits;
  for (const auto& item : in.positions) {
    auto key = detail::normalized_hex(item.pubkey);
    auto holder = detail::normalized_hex(item.holder);
    require(keys.insert(key).second, "duplicate validator pubkey in round");
    Nano principal = detail::amount(item.selected_principal, true);
    Nano stake = detail::amount(item.pre_unfreeze_stake);
    require(item.banned.has_value(), "missing banned flag");
    require(stake <= principal, "pre-unfreeze stake exceeds selected principal");
    require(!*item.banned, "banned entry has no reviewed code/version mapping");
    require(item.selected_at == selection.gen_utime && item.unfrozen_at == post.gen_utime,
            "position timestamps disagree with proven MC anchors");
    auto seconds = detail::duration(item.selected_at, item.unfrozen_at);
    Nano returned = stake;  // only non-banned studied version is currently supported
    Nano bonus = bonuses == 0 ? Nano(0) : bonuses * stake / total;
    Nano fine = principal - stake;
    Nano uncredited = stake - returned;
    Nano loss = principal - returned;
    expected_credits[holder] += returned + bonus;
    out.positions.push_back({network, in.election_id, vset, key, holder, principal, stake, returned,
                             fine, uncredited, loss, bonus, seconds,
                             detail::rate(bonus, principal, principal * seconds),
                             detail::rate(bonus - loss, principal, principal * seconds)});
    out.principal += principal;
    out.pre_unfreeze += stake;
    out.returned += returned;
    out.fine += fine;
    out.uncredited_stake += uncredited;
    out.loss += loss;
    out.awarded_bonus += bonus;
    out.stake_seconds += principal * seconds;
  }
  require(out.principal == original && out.pre_unfreeze == total, "frozen stake sum mismatch");
  require(out.awarded_bonus <= bonuses, "awarded bonuses exceed reserve");
  out.undistributed_bonus = bonuses - out.awarded_bonus;

  std::map<std::string, Nano> actual_credits;
  for (const auto& c : in.credits) {
    auto holder = detail::normalized_hex(c.holder);
    Nano before = detail::amount(c.before);
    Nano after = detail::amount(c.after);
    require(actual_credits.emplace(holder, after - before).second, "duplicate holder credits");
  }
  // Exact map comparison also catches ANY unexpected changed holder and
  // requires an explicit zero-delta record for a banned-only holder.
  require(actual_credits == expected_credits, "holder credit delta mismatch or extra changes");
  out.gross = detail::rate(out.awarded_bonus, out.principal, out.stake_seconds);
  out.net = detail::rate(out.awarded_bonus - out.loss, out.principal, out.stake_seconds);
  return out;
}

}  // namespace tonstat::validators::yield
