#include "WalletMetrics.h"

// Keep regression assertions active even when compiling the reducer with -DNDEBUG.
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <cassert>
#include <iostream>
#include <stdexcept>
#include <string>
#include <utility>

using namespace ton_analytics::wallets;
namespace {
constexpr std::int64_t day_seconds = 86400;

BlockId mc(unsigned n, std::string hash = "") {
  if (hash.empty()) hash = "mc" + std::to_string(n);
  return {-1, 0x8000000000000000ULL, n, hash, hash + "file"};
}
BlockId shard(unsigned n, std::uint64_t partition = 8, std::string hash = "") {
  if (hash.empty()) hash = "s" + std::to_string(partition) + ":" + std::to_string(n);
  return {0, partition, n, hash, hash + "file"};
}
Scope scope() {
  return {"testnet", "verified-zerostate-root", "verified-zerostate-file",
          "wallet-v1", "registry-sha", {0}};
}
CodeEvidence wallet() { return {EvidenceKind::qualified, "wallet-hash", "v5", "verified pre-state"}; }
CodeEvidence excluded() { return {EvidenceKind::excluded, "preprocessed-hash", "", "verified pre-state"}; }

LifetimeBaseline genesis() {
  LifetimeBaseline b;
  b.scope = scope();
  b.mc = mc(0);
  b.shard_tips = {{shard(0), 0}};
  b.canonical_anchor_verified = b.full_history_verified = b.all_initial_accounts_verified = true;
  b.shard_frontier_verified = true;
  b.attestation_id = "verified-genesis-and-complete-account-set";
  return b;
}

EventRangeCheckpoint event_checkpoint(unsigned n, std::int64_t time) {
  EventRangeCheckpoint c;
  c.scope = scope();
  c.mc = mc(n);
  c.mc_utime = time;
  c.shard_tips = {{shard(n), time}};
  c.canonical_anchor_verified = true;
  c.independent_frontier_verified = true;
  c.complete_event_left_boundary_verified = true;
  c.canonical_anchor_attestation = "external MC canonical proof";
  c.independent_frontier_attestation = "external complete tip proof";
  c.event_left_boundary_attestation = "external event-left proof";
  return c;
}

WalletObservation observation(std::string account, unsigned lt, std::int64_t time,
                              BlockId block, AccountStatus orig, AccountStatus end,
                              CodeEvidence activation = {}, bool sent = false,
                              CodeEvidence execution = {}) {
  WalletObservation o;
  o.account = std::move(account);
  o.lt = lt;
  o.tx_hash = "tx" + o.account + std::to_string(lt);
  o.now = time;
  o.block = std::move(block);
  o.orig = orig;
  o.end = end;
  o.activation_code = std::move(activation);
  o.execution_code = std::move(execution);
  o.actual_qualifying_outgoing = sent;
  if (sent) o.outgoing_message_hash = "msg" + o.tx_hash;
  return o;
}

BlockEnvelope block(unsigned n, std::int64_t mc_time, std::int64_t shard_time,
                    std::vector<WalletObservation> observations = {}) {
  BlockEnvelope e;
  e.scope = scope();
  e.mc = mc(n);
  e.prev_mc = mc(n - 1);
  e.mc_utime = mc_time;
  e.new_shard_blocks = {{shard(n), {shard(n - 1)}, shard_time, true, true, true}};
  e.current_shard_tips = {{shard(n), shard_time}};
  e.graph_diff_verified = e.time_rules_verified = true;
  e.graph_diff_attestation = "independent graph proof " + std::to_string(n);
  e.time_rules_attestation = "independent time proof " + std::to_string(n);
  e.tx_inventory_attestation = "independent tx inventory " + std::to_string(n);
  e.mc_transactions_complete = e.mc_activation_inputs_complete = e.mc_activity_inputs_complete = true;
  e.observations = std::move(observations);
  e.revision = 1;
  return e;
}

template <class F> void rejected(F&& f) {
  bool threw = false;
  try { f(); } catch (const std::invalid_argument&) { threw = true; }
  assert(threw);
}

void network_identity_requires_both_zerostate_hashes() {
  auto missing_root = scope();
  missing_root.zerostate_root_hash.clear();
  rejected([&] { WalletMetrics m(missing_root); });
  auto missing_file = scope();
  missing_file.zerostate_file_hash.clear();
  rejected([&] { WalletMetrics m(missing_file); });

  WalletMetrics m(scope());
  auto different_file = scope();
  different_file.zerostate_file_hash = "other-file";
  auto e = block(1, 1, 1);
  e.scope = different_file;
  rejected([&] { m.put(e); });
  auto checkpoint = event_checkpoint(1, 1);
  checkpoint.scope = different_file;
  rejected([&] { m.set_event_checkpoint(checkpoint); });
  auto different_root = scope();
  different_root.zerostate_root_hash = "other-root";
  auto baseline = genesis();
  baseline.scope = different_root;
  rejected([&] { m.set_baseline(baseline); });
  assert(m.generation() == 0 && !m.contiguous_watermark());

  m.set_event_checkpoint(event_checkpoint(1, 1));
  m.put(block(2, day_seconds + 1, day_seconds + 1));
  m.put(block(3, 2 * day_seconds, 2 * day_seconds));
  assert(m.day(day_seconds).dau == 0);
  assert(!m.day(day_seconds).daily_activations); // file identity does not grant lifetime
}

void first_active_even_if_not_wallet() {
  WalletMetrics metrics(scope());
  auto b = genesis();
  b.genesis_active_accounts.insert("Z");
  metrics.set_baseline(b);
  auto e1 = block(1, 10, 10, {
      observation("N", 1, 10, shard(1), AccountStatus::nonexist, AccountStatus::active, excluded()),
      observation("X", 2, 10, shard(1), AccountStatus::uninit, AccountStatus::active, excluded()),
      observation("W", 3, 10, shard(1), AccountStatus::uninit, AccountStatus::active, wallet()),
      observation("Z", 4, 10, shard(1), AccountStatus::uninit, AccountStatus::active, wallet()),
  });
  auto e2 = block(2, day_seconds + 2, day_seconds + 2, {
      observation("N", 5, day_seconds + 2, shard(2), AccountStatus::uninit, AccountStatus::active, wallet()),
      observation("X", 6, day_seconds + 2, shard(2), AccountStatus::uninit, AccountStatus::active, wallet()),
  });
  metrics.put(e2); // deliberately out of order
  assert(!metrics.day(0).daily_activations);
  metrics.put(e1);
  assert(metrics.contiguous_watermark() == mc(2));
  assert(metrics.first_active("N")->witness.lt == 1);
  assert(metrics.first_active("X")->witness.activation_code.kind == EvidenceKind::excluded);
  assert(metrics.first_active("Z")->genesis_state);
  auto d = metrics.day(0);
  assert(d.daily_activations == 1 && d.cumulative_activations == 1);
  assert(d.activation_types.at("v5") == 1);
  metrics.put(block(3, 2 * day_seconds, 2 * day_seconds));
  assert(metrics.day(day_seconds).daily_activations == 0);
}

void activity_exact_union_and_independent_readiness() {
  WalletMetrics m(scope());
  m.set_baseline(genesis());
  for (unsigned i = 0; i <= 31; ++i) {
    const auto time = std::int64_t(i) * day_seconds + 1;
    std::vector<WalletObservation> obs;
    auto send = [&](std::string account, unsigned suffix) {
      obs.push_back(observation(std::move(account), i * 100 + suffix, time, shard(i + 1),
                                AccountStatus::active, AccountStatus::active, {}, true, wallet()));
    };
    if (i == 0) { send("A", 1); send("B", 2); send("A", 3); }
    if (i == 1) { send("A", 1); send("C", 2); }
    if (i == 29) send("B", 1);
    auto e = block(i + 1, time, time, std::move(obs));
    if (i == 10) { // unknown execution only blocks day 10 and windows containing it
      e.observations.push_back(observation("U", 1007, time, shard(i + 1),
                                         AccountStatus::active, AccountStatus::active, {}, true));
    }
    if (i == 12) { // unresolved status doesn't prevent a known DAU
      e.new_shard_blocks.front().activation_inputs_complete = false;
    }
    m.put(e);
  }
  assert(m.day(0).dau == 2);
  assert(m.day(day_seconds).dau == 2);
  auto d29 = m.day(29 * day_seconds);
  assert(d29.dau == 1);
  assert(!d29.mau_30d); // day 10 unknown, not "three" and not zero
  assert(!d29.cumulative_activations); // day 12 missing activation status
  assert(m.day(12 * day_seconds).dau == 0);
  assert(!m.day(10 * day_seconds).dau);

  auto corrected10 = block(11, 10 * day_seconds + 1, 10 * day_seconds + 1);
  corrected10.revision = 2; // explicitly remove unresolved tx from COMPLETE revision
  m.put(corrected10);
  assert(m.day(29 * day_seconds).mau_30d.has_value()); // independent of activation status
  assert(m.day(29 * day_seconds).mau_30d == 3); // union {A,B,C}, not 2+2+1
  assert(m.day(30 * day_seconds).mau_30d == 3);
  auto revised_day1 = block(2, day_seconds + 1, day_seconds + 1, {
      observation("A", 101, day_seconds + 1, shard(2), AccountStatus::active,
                  AccountStatus::active, {}, true, wallet())});
  revised_day1.revision = 2; // replaces complete scope, removing C
  m.put(revised_day1);
  assert(m.day(29 * day_seconds).mau_30d == 2);
  assert(m.day(30 * day_seconds).mau_30d == 2);
  revised_day1.revision = 3;
  revised_day1.new_shard_blocks.front().activity_inputs_complete = false;
  m.put(revised_day1);
  assert(!m.day(29 * day_seconds).mau_30d);
  assert(!m.day(30 * day_seconds).mau_30d);
  assert(m.day(0).dau == 2); // unaffected day stays ready
  revised_day1.revision = 4;
  revised_day1.new_shard_blocks.front().activity_inputs_complete = true;
  m.put(revised_day1);
  auto corrected12 = block(13, 12 * day_seconds + 1, 12 * day_seconds + 1);
  corrected12.revision = 2;
  m.put(corrected12);
  assert(m.day(29 * day_seconds).cumulative_activations == 0);
}

void frontier_split_merge_repeated_tips() {
  WalletMetrics m(scope());
  m.set_baseline(genesis());
  auto e1 = block(1, day_seconds - 1, day_seconds - 1);
  m.put(e1);
  auto e2 = block(2, day_seconds, day_seconds - 1); // MC crossed midnight; shard did not
  e2.new_shard_blocks.clear();
  e2.current_shard_tips = {{shard(1), day_seconds - 1}};
  m.put(e2);
  assert(!m.day(0).dau);
  auto e3 = block(3, day_seconds + 1, day_seconds);
  e3.new_shard_blocks = {
      {shard(2, 4), {shard(1)}, day_seconds, true, true, true},
      {shard(2, 12), {shard(1)}, day_seconds, true, true, true},
  };
  e3.current_shard_tips = {{shard(2, 4), day_seconds}, {shard(2, 12), day_seconds}};
  m.put(e3);
  assert(m.day(0).dau == 0);
  auto e4 = block(4, day_seconds + 2, day_seconds + 2);
  e4.new_shard_blocks = {{shard(3), {shard(2, 4), shard(2, 12)},
                          day_seconds + 2, true, true, true}};
  e4.current_shard_tips = {{shard(3), day_seconds + 2}};
  m.put(e4);
  assert(m.contiguous_watermark() == mc(4));
  auto e5 = block(5, day_seconds + 3, day_seconds + 2);
  e5.new_shard_blocks.clear();
  e5.current_shard_tips = {{shard(3), day_seconds + 2}};
  m.put(e5);
  assert(m.contiguous_watermark() == mc(5));
  assert(m.day(0).daily_activations == 0);

  WalletMetrics incomplete(scope());
  incomplete.set_baseline(genesis());
  incomplete.put(e1);
  incomplete.put(e2);
  auto lost_child = e3;
  lost_child.new_shard_blocks.pop_back();
  incomplete.put(lost_child); // listed tip not explained by new blocks
  assert(incomplete.contiguous_watermark() == mc(2));
  assert(!incomplete.day(0).dau);
  e3.revision = 2;
  incomplete.put(e3);
  assert(incomplete.day(0).dau == 0);
}

void gaps_conflicts_and_revision() {
  WalletMetrics pilot(scope());
  pilot.put(block(1, 1, 1));
  pilot.put(block(2, day_seconds, day_seconds));
  assert(!pilot.day(0).daily_activations && !pilot.contiguous_watermark());
  auto invalid = genesis();
  invalid.full_history_verified = false;
  rejected([&] { pilot.set_baseline(invalid); });
  pilot.set_baseline(genesis());
  assert(pilot.day(0).dau == 0);

  WalletMetrics m(scope());
  m.set_baseline(genesis());
  auto e1 = block(1, 1, 1, {
      observation("A", 1, 1, shard(1), AccountStatus::nonexist, AccountStatus::active, excluded())});
  auto e2 = block(2, day_seconds + 1, day_seconds + 1, {
      observation("A", 2, day_seconds + 1, shard(2), AccountStatus::uninit,
                  AccountStatus::active, wallet())});
  auto e3 = block(3, 2 * day_seconds, 2 * day_seconds);
  m.put(e1);
  m.put(e2);
  m.put(e3);
  assert(m.day(day_seconds).daily_activations == 0);
  auto before = m.generation();
  m.put(e2);
  assert(m.generation() == before);
  auto conflicting = e2;
  conflicting.observations.front().tx_hash = "other hash";
  rejected([&] { m.put(conflicting); });
  auto correction = e1;
  correction.revision = 2;
  correction.observations.clear(); // tombstone by complete revision replacement
  m.put(correction);
  assert(m.first_active("A")->witness.lt == 2);
  auto d = m.day(day_seconds);
  assert(d.daily_activations == 1 && d.cumulative_activations == 1);
  assert(d.generation > before);
  m.put(e1); // late old revision cannot restore removed fact
  assert(m.day(day_seconds).daily_activations == 1);
  correction = e2;
  correction.revision = 2;
  correction.observations.clear();
  m.put(correction);
  assert(m.day(day_seconds).daily_activations == 0);
  assert(m.day(day_seconds).cumulative_activations == 0);

  WalletMetrics gap(scope());
  gap.set_baseline(genesis());
  auto bad_link = block(2, day_seconds, day_seconds);
  bad_link.prev_mc = mc(1, "wrong-root"); // seqno alone cannot certify predecessor
  gap.put(bad_link);
  gap.put(block(1, 1, 1));
  assert(gap.contiguous_watermark() == mc(1));
  assert(!gap.day(0).dau);
  bad_link = block(2, day_seconds, day_seconds);
  bad_link.revision = 2;
  gap.put(bad_link);
  assert(gap.contiguous_watermark() == mc(2));

  auto duplicate = block(3, day_seconds + 1, day_seconds + 1, {
      observation("A", 7, day_seconds + 1, shard(3), AccountStatus::uninit,
                  AccountStatus::active, wallet())});
  auto duplicate_same_lt = duplicate.observations.front();
  duplicate_same_lt.tx_hash = "conflicting-hash";
  duplicate.observations.push_back(duplicate_same_lt);
  rejected([&] { gap.put(duplicate); });

  auto distinct_mc = block(3, day_seconds + 1, day_seconds + 1, {
      observation("A", 7, day_seconds + 1, shard(3), AccountStatus::uninit,
                  AccountStatus::active, wallet())});
  gap.put(distinct_mc);
  auto next = block(4, day_seconds + 2, day_seconds + 2, {
      observation("A", 7, day_seconds + 2, shard(4), AccountStatus::uninit,
                  AccountStatus::active, wallet())});
  rejected([&] { gap.put(next); }); // same address+LT, distinct tx hash/block

  WalletMetrics bounded(scope(), 1, 1);
  bounded.set_baseline(genesis());
  bounded.put(block(1, 1, 1));
  rejected([&] { bounded.put(block(2, day_seconds, day_seconds)); });
}

void historical_bootstrap_requires_complete_first_witnesses() {
  auto b = genesis();
  b.kind = BaselineKind::verified_historical_bootstrap;
  b.mc = mc(42);
  b.mc_utime = 40 * day_seconds;
  b.shard_tips = {{shard(42), 40 * day_seconds}};
  b.first_active_history = {observation("A", 1, 2, shard(1), AccountStatus::nonexist,
                                        AccountStatus::active, excluded())};
  b.attestation_id = "audited-complete-status-and-canonical-history-through-MC42";
  WalletMetrics m(scope());
  m.set_baseline(b);
  auto e = block(43, 41 * day_seconds + 1, 41 * day_seconds + 1, {
      observation("A", 99, 41 * day_seconds + 1, shard(43), AccountStatus::uninit,
                  AccountStatus::active, wallet())});
  e.prev_mc = mc(42);
  e.new_shard_blocks.front().predecessors = {shard(42)};
  m.put(e);
  auto close = block(44, 42 * day_seconds, 42 * day_seconds);
  close.prev_mc = mc(43);
  m.put(close);
  assert(m.day(41 * day_seconds).daily_activations == 0);
  assert(!m.day(40 * day_seconds).dau); // checkpoint does not fill historical activity

  auto conflict = b;
  conflict.first_active_history.front().tx_hash = "different";
  rejected([&] { m.set_baseline(conflict); });
  conflict.attestation_id = "second-certificate";
  m.set_baseline(conflict); // explicit new certificate replaces historical witness
  assert(m.first_active("A")->witness.tx_hash == "different");

  auto impossible = block(45, 42 * day_seconds + 1, 42 * day_seconds + 1, {
      observation("A", 0, 42 * day_seconds + 1, shard(45), AccountStatus::active,
                  AccountStatus::active)});
  rejected([&] { m.put(impossible); }); // cannot predate attested first active by LT
  WalletMetrics overlap(scope());
  overlap.put(block(1, 1, 1));
  rejected([&] { overlap.set_baseline(b); }); // CH baseline cannot launder pilot blocks
}

void unknown_is_not_zero_and_activity_uses_execution_code() {
  WalletMetrics m(scope());
  m.set_baseline(genesis());
  auto e1 = block(1, 1, 1, {
      observation("U", 1, 1, shard(1), AccountStatus::uninit, AccountStatus::active),
      observation("E", 2, 1, shard(1), AccountStatus::active, AccountStatus::nonexist,
                  excluded(), true, wallet()), // sender self-destructed: execution code counts
      observation("P", 3, 1, shard(1), AccountStatus::active, AccountStatus::active,
                  wallet(), true, excluded()), // excluded execution does NOT count
      observation("S", 4, 1, shard(1), AccountStatus::active, AccountStatus::active,
                  wallet(), true), // unresolved execution blocks DAU
  });
  m.put(e1);
  m.put(block(2, day_seconds, day_seconds));
  assert(!m.day(0).daily_activations);
  assert(!m.day(0).cumulative_activations);
  assert(!m.day(0).dau);
  auto fix = e1;
  fix.revision = 2;
  fix.observations.front().activation_code = excluded();
  fix.observations.back().execution_code = excluded();
  m.put(fix);
  assert(m.day(0).daily_activations == 0);
  assert(m.day(0).dau == 1);
  assert(m.first_active("E")->witness.end == AccountStatus::nonexist);
  rejected([&] {
    auto bad = fix;
    bad.revision = 3;
    bad.observations[1].outgoing_message_hash.clear();
    m.put(bad); // cannot invent activity from an unproven message
  });
}

void event_checkpoint_does_not_certify_lifetime() {
  WalletMetrics pilot(scope());
  auto first = block(1, 1, 1);
  auto second = block(2, day_seconds + 1, day_seconds + 1);
  pilot.put(first);
  pilot.put(second);
  assert(!pilot.day(0).daily_activations && !pilot.day(0).dau);
  assert(!pilot.day(day_seconds).dau);
  auto forged = event_checkpoint(1, 1);
  forged.event_left_boundary_attestation.clear();
  rejected([&] { pilot.set_event_checkpoint(forged); });
  forged = event_checkpoint(2, day_seconds + 1);
  rejected([&] { pilot.set_event_checkpoint(forged); }); // cannot launder existing slices

  WalletMetrics m(scope());
  auto c = event_checkpoint(1, 1);
  for (unsigned i = 0; i < 6; ++i) {
    auto unproved = c;
    if (i == 0) unproved.canonical_anchor_verified = false;
    if (i == 1) unproved.independent_frontier_verified = false;
    if (i == 2) unproved.complete_event_left_boundary_verified = false;
    if (i == 3) unproved.canonical_anchor_attestation.clear();
    if (i == 4) unproved.independent_frontier_attestation.clear();
    if (i == 5) unproved.event_left_boundary_attestation = unproved.canonical_anchor_attestation;
    rejected([&] { m.set_event_checkpoint(unproved); });
  }
  m.set_event_checkpoint(c);
  m.set_event_checkpoint(c); // idempotent independent certificate
  auto e2 = block(2, day_seconds + 1, day_seconds + 1, {
      observation("A", 20, day_seconds + 1, shard(2), AccountStatus::uninit,
                  AccountStatus::active, wallet(), true, wallet())});
  m.put(e2);
  m.put(block(3, 2 * day_seconds, 2 * day_seconds));
  auto result = m.day(day_seconds);
  assert(result.dau == 1);
  assert(!result.daily_activations && !result.cumulative_activations);
  assert(!result.mau_30d); // no 30-day left frontier
  assert(!m.first_active("A")); // without a lifetime baseline, NEVER a first-active fact

  auto bad_proof = e2;
  bad_proof.revision = 2;
  bad_proof.tx_inventory_attestation.clear();
  m.put(bad_proof);
  assert(!m.day(day_seconds).dau); // flags alone are not proof
  bad_proof.revision = 3;
  bad_proof.tx_inventory_attestation = "independent corrected inventory";
  m.put(bad_proof);
  assert(m.day(day_seconds).dau == 1);

  WalletMetrics full_window(scope());
  auto start = event_checkpoint(1, 1);
  full_window.set_event_checkpoint(start);
  for (unsigned i = 1; i <= 31; ++i) {
    const auto when = i * day_seconds + 1;
    std::vector<WalletObservation> tx;
    if (i == 1 || i == 2 || i == 30)
      tx.push_back(observation(i == 30 ? "B" : "A", i + 100, when, shard(i + 1),
                               AccountStatus::active, AccountStatus::active, {}, true, wallet()));
    full_window.put(block(i + 1, when, when, std::move(tx)));
  }
  assert(!full_window.day(29 * day_seconds).mau_30d); // day 0 unproven
  assert(full_window.day(30 * day_seconds).mau_30d == 2); // days 1..30 exact union
  assert(!full_window.day(30 * day_seconds).cumulative_activations);
}

void event_right_boundary_and_unknown_are_independent_of_lifetime() {
  WalletMetrics m(scope());
  m.set_event_checkpoint(event_checkpoint(1, 1));
  const auto start = day_seconds;
  auto e2 = block(2, start + 2, start + 2, {
      observation("A", 1, start + 2, shard(2), AccountStatus::active,
                  AccountStatus::active, {}, true, wallet()),
      observation("U", 2, start + 2, shard(2), AccountStatus::active,
                  AccountStatus::active, {}, true)});
  m.put(e2);
  auto no_shard_boundary = block(3, 2 * day_seconds, start + 2);
  no_shard_boundary.new_shard_blocks.clear();
  no_shard_boundary.current_shard_tips = {{shard(2), start + 2}};
  m.put(no_shard_boundary);
  assert(m.event_watermark() == mc(3));
  assert(!m.day(start).dau); // MC midnight alone is not the full shard right boundary

  auto e4 = block(4, 2 * day_seconds + 1, 2 * day_seconds);
  e4.new_shard_blocks.front().predecessors = {shard(2)};
  m.put(e4);
  assert(m.event_watermark() == mc(4));
  assert(!m.day(start).dau); // unresolved qualifying send cannot become zero
  auto fixed = e2;
  fixed.revision = 2;
  fixed.observations.back().execution_code = excluded();
  m.put(fixed);
  const auto generation = m.generation();
  m.put(fixed);
  m.put(e2); // stale old revision must not undo resolution
  assert(m.generation() == generation);
  assert(m.day(start).dau == 1);
  assert(!m.day(start).daily_activations && !m.day(start).cumulative_activations);
  assert(!m.day(start).mau_30d); // event proof did not cover the 30-day left edge
}

void genesis_first_utc_day_and_short_mau() {
  auto b = genesis();
  const auto origin = 4 * day_seconds + 13;
  b.mc_utime = origin;
  b.shard_tips = {{shard(0), origin}};
  auto future_tip = b;
  future_tip.shard_tips.front().gen_utime = 5 * day_seconds;
  WalletMetrics invalid(scope());
  rejected([&] { invalid.set_baseline(future_tip); }); // would skip part of the first UTC day
  WalletMetrics m(scope());
  m.set_baseline(b);
  m.put(block(1, origin + 1, origin + 1, {
      observation("A", 1, origin + 1, shard(1), AccountStatus::uninit,
                  AccountStatus::active, wallet(), true, wallet())}));
  m.put(block(2, 5 * day_seconds, 5 * day_seconds));
  assert(!m.day(3 * day_seconds).dau);
  assert(!m.day(3 * day_seconds).mau_30d);
  assert(!m.day(3 * day_seconds).daily_activations);
  assert(m.day(4 * day_seconds).daily_activations == 1);
  assert(m.day(4 * day_seconds).dau == 1);
  assert(m.day(4 * day_seconds).mau_30d == 1); // pre-genesis days are empty, not missing
  m.put(block(3, 5 * day_seconds + 1, 5 * day_seconds + 1, {
      observation("B", 2, 5 * day_seconds + 1, shard(3), AccountStatus::active,
                  AccountStatus::active, {}, true, wallet())}));
  m.put(block(4, 6 * day_seconds, 6 * day_seconds));
  assert(m.day(5 * day_seconds).mau_30d == 2);
}

void unordered_multi_block_diff_is_topologically_verified() {
  WalletMetrics m(scope());
  m.set_baseline(genesis());
  m.put(block(1, day_seconds - 1, day_seconds - 1));
  auto chain = block(2, day_seconds + 2, day_seconds + 1, {
      observation("A", 12, day_seconds + 2, shard(3), AccountStatus::active,
                  AccountStatus::active, {}, true, wallet())});
  chain.new_shard_blocks = {
      {shard(3), {shard(2)}, day_seconds + 2, true, true, true},
      {shard(2), {shard(1)}, day_seconds + 1, true, true, true},
  }; // deliberately child BEFORE parent, while MC anchor is 2
  chain.current_shard_tips = {{shard(3), day_seconds + 2}};
  m.put(chain);
  assert(m.contiguous_watermark() == mc(2));
  assert(m.day(0).dau == 0);

  auto missing_parent = chain;
  missing_parent.revision = 2;
  missing_parent.new_shard_blocks.pop_back();
  m.put(missing_parent);
  assert(m.contiguous_watermark() == mc(1));
  assert(!m.day(0).dau);
  chain.revision = 3;
  m.put(chain);
  assert(m.day(0).dau == 0);

  auto duplicate = block(3, day_seconds + 3, day_seconds + 3);
  duplicate.new_shard_blocks.front().id = shard(2); // same earlier ID already consumed
  duplicate.new_shard_blocks.front().predecessors = {shard(3)};
  duplicate.current_shard_tips = {{shard(2), day_seconds + 3}};
  m.put(duplicate);
  assert(m.contiguous_watermark() == mc(2));

  WalletMetrics conflicting_coordinates(scope());
  conflicting_coordinates.set_baseline(genesis());
  conflicting_coordinates.put(block(1, day_seconds - 1, day_seconds - 1));
  auto fork = chain;
  fork.observations.clear();
  fork.new_shard_blocks = {
      {shard(3), {shard(2), shard(2, 8, "forked")}, day_seconds + 2, true, true, true},
      {shard(2, 8, "forked"), {shard(1)}, day_seconds + 1, true, true, true},
      {shard(2), {shard(1)}, day_seconds + 1, true, true, true},
  };
  conflicting_coordinates.put(fork);
  assert(conflicting_coordinates.contiguous_watermark() == mc(1));
  auto ambiguous_tips = chain;
  ambiguous_tips.observations.clear();
  ambiguous_tips.current_shard_tips = {{shard(3), day_seconds + 2},
                                       {shard(3, 8, "forked"), day_seconds + 2}};
  rejected([&] { conflicting_coordinates.put(ambiguous_tips); });
}
} // namespace

int main() {
  network_identity_requires_both_zerostate_hashes();
  first_active_even_if_not_wallet();
  activity_exact_union_and_independent_readiness();
  frontier_split_merge_repeated_tips();
  gaps_conflicts_and_revision();
  historical_bootstrap_requires_complete_first_witnesses();
  unknown_is_not_zero_and_activity_uses_execution_code();
  event_checkpoint_does_not_certify_lifetime();
  event_right_boundary_and_unknown_are_independent_of_lifetime();
  genesis_first_utc_day_and_short_mau();
  unordered_multi_block_diff_is_topologically_verified();
  std::cout << "wallet metrics offline tests passed\n";
}
