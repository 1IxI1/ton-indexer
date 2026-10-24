#include "Accounts.h"

#include <cassert>
#include <functional>
#include <iostream>

using namespace tonstat::accounts;

namespace {
std::string hash(char c) { return std::string(64, c); }
BlockId id(int wc, std::uint64_t shard, int seq, char root) {
  return {wc, shard, static_cast<unsigned>(seq), hash(root), hash('e')};
}
Tip tip(BlockId b, char state) { return {b, hash(state)}; }
Anchor anchor(int seq, BlockId shard) {
  auto mc = id(-1, 1, seq, seq == 1 ? 'a' : seq == 2 ? 'b' : seq == 3 ? 'c' : seq == 4 ? '6' : '8');
  return {"fixture", hash('0'), mc, hash('d'), {tip(mc, 'd'), tip(shard, 'f')}};
}
Snapshot baseline() {
  Snapshot s;
  s.anchor = anchor(1, id(0, 1, 10, '1'));
  s.counts = {2, 1, 1};
  s.visited = 4;
  s.scanned_tips = 2;
  finish_snapshot(s, true, true); // synthetic *fully scanned* fixture, never a live certificate
  return s;
}
void fails(const std::function<void()>& op) {
  try { op(); } catch (const std::exception&) { return; }
  assert(false && "expected fail-closed error");
}
Tx tx(std::string address, std::uint64_t lt, Status before, Status after, int wc = 0) {
  return {{wc, std::move(address)}, lt, hash('9'), before, after,
          lt - 1, hash(lt == 1 ? '0' : '9'),
          hash(lt == 1 ? '0' : static_cast<char>('a' + lt - 2)),
          hash(static_cast<char>('a' + lt - 1))};
}
NewBlock block(BlockId b, std::vector<BlockId> prev, std::vector<Tx> txs,
               char old_state, char post_state) {
  return {std::move(b), std::move(prev), std::move(txs), hash(old_state), hash(post_state)};
}
Step next(const Snapshot& s, int seq, BlockId shard, std::vector<NewBlock> blocks) {
  Step step{anchor(seq, shard), s.anchor.mc, std::move(blocks)};
  step.inclusion_and_topology_verified = true;
  step.raw_identity_verified = true;
  step.state_linkage_verified = true;
  step.baseline_witnesses_verified = true;
  return step;
}
} // namespace

int main() {
  {
    auto sample = baseline();
    sample.scanned_tips = 1;
    finish_snapshot(sample, true, true);
    assert(sample.readiness == Readiness::incomplete);
    sample.scanned_tips = 2;
    finish_snapshot(sample, false, true);
    assert(sample.readiness == Readiness::incomplete);
    finish_snapshot(sample, true, false);
    assert(sample.readiness == Readiness::incomplete);
    sample.visited = 5;
    fails([&] { finish_snapshot(sample, true, true); });
    fails([&] { Counter(sample).apply({}); });
  }
  auto b = baseline();
  Counter counter(b);
  auto mc2 = id(-1, 1, 2, 'b');
  auto shard11 = id(0, 1, 11, '2');
  const auto a = hash('1'), z = hash('2');
  // Same account: nonexist -> uninit -> active -> nonexist; exact per-tx
  // sequencing, no lifetime-distinct counting and no double-counted deletion.
  auto ztx = tx(z, 4, Status::frozen, Status::active);
  ztx.prev_hash = hash('8');
  auto s2 = next(b, 2, shard11, {
    block(shard11, {b.anchor.tips[1].id}, {tx(a, 3, Status::active, Status::nonexist),
                                     tx(a, 1, Status::nonexist, Status::uninit),
                                     tx(a, 2, Status::uninit, Status::active),
                                     ztx}, 'f', 'f'),
    block(mc2, {b.anchor.mc}, {tx(hash('3'), 1, Status::active, Status::frozen, -1)}, 'd', 'd')
  });
  s2.baseline_witnesses = {
    {{0, a}, {Status::nonexist, 0, hash('0'), hash('0')}},
    {{0, z}, {Status::frozen, 3, hash('8'), hash('c')}},
    {{-1, hash('3')}, {Status::active, 0, hash('0'), hash('0')}}
  };
  counter.apply(s2);
  assert((counter.current().counts == Counts{2, 1, 1}));
  assert(counter.current().readiness == Readiness::complete);
  fails([&] { counter.apply(s2); }); // retry must not increment
  auto bad = next(b, 2, shard11, s2.newly_included);
  bad.inclusion_and_topology_verified = false;
  fails([&] { Counter(b).apply(bad); });
  bad = s2;
  bad.newly_included.pop_back();
  fails([&] { Counter(b).apply(bad); }); // MC missing
  bad = s2;
  bad.newly_included[0].transactions[2].before = Status::frozen;
  fails([&] { Counter(b).apply(bad); }); // uninit -> active chain broken
  bad = s2;
  bad.newly_included[0].transactions.push_back(bad.newly_included[0].transactions[0]);
  fails([&] { Counter(b).apply(bad); }); // duplicated account LT
  bad = s2;
  bad.newly_included[0].prev = {id(0, 1, 999, '7')};
  fails([&] { Counter(b).apply(bad); }); // missing ancestor
  bad = s2;
  bad.newly_included[0].old_state_hash = hash('e');
  fails([&] { Counter(b).apply(bad); }); // bogus raw shard old_hash
  bad = s2;
  bad.raw_identity_verified = false;
  fails([&] { Counter(b).apply(bad); }); // failed BoC file hash/header verification
  bad = s2;
  bad.baseline_witnesses.erase({0, a});
  fails([&] { Counter(b).apply(bad); }); // first tx must match baseline membership
  bad = s2;
  bad.baseline_witnesses[{0, a}].status = Status::active;
  fails([&] { Counter(b).apply(bad); });
  bad = s2;
  bad.baseline_witnesses_verified = false;
  fails([&] { Counter(b).apply(bad); }); // even correct unauthenticated witness is pending
  bad = s2;
  bad.newly_included[0].transactions[0].prev_hash = hash('e');
  fails([&] { Counter(b).apply(bad); });
  bad = s2;
  bad.newly_included[0].transactions[0].prev_lt = 0;
  fails([&] { Counter(b).apply(bad); });
  fails([&] { Counter(b, Caps{1, 50, 50}).apply(s2); });
  fails([&] { Counter(b, Caps{50, 3, 50}).apply(s2); });
  fails([&] { Counter(b, Caps{50, 50, 2}).apply(s2); });
  assert((b.counts == Counts{2, 1, 1})); // rejected step never commits
  // Previous tip repeats at next MC: only new MC; no double-counted shard tx.
  auto s3 = next(counter.current(), 3, shard11, {
    block(id(-1, 1, 3, 'c'), {mc2}, {}, 'd', 'd')
  });
  counter.apply(s3);
  assert((counter.current().counts == Counts{2, 1, 1}));
  auto shard12 = id(0, 1, 12, '4');
  auto follow = next(counter.current(), 4, shard12, {
    block(shard12, {shard11}, {tx(z, 5, Status::active, Status::frozen)}, 'f', 'f'),
    block(id(-1, 1, 4, '6'), {counter.current().anchor.mc}, {}, 'd', 'd')
  });
  auto corrupt = follow;
  corrupt.newly_included[0].transactions[0].lt = 4;
  fails([&] { counter.apply(corrupt); }); // repeated/decreasing LT across blocks
  corrupt = follow;
  corrupt.newly_included[0].transactions[0].prev_hash = hash('e');
  fails([&] { counter.apply(corrupt); }); // wrong previous tx hash across blocks
  corrupt = follow;
  corrupt.newly_included[0].transactions[0].prev_lt = 3;
  fails([&] { counter.apply(corrupt); });
  corrupt = follow;
  corrupt.newly_included[0].transactions[0].old_state_hash = hash('e');
  fails([&] { counter.apply(corrupt); });
  assert(counter.current().anchor.mc.seqno == 3); // failures atomic
  Counter followed = counter;
  followed.apply(follow);
  assert((followed.current().counts == Counts{2, 0, 2}));
  // Neither split nor merge has a certified old-state transform in the native
  // adapter. Even a structurally plausible frontier MUST remain pending.
  auto left = id(0, 2, 12, '4'), right = id(0, 3, 12, '5');
  auto split = next(counter.current(), 4, left, {
    block(id(-1, 1, 4, '6'), {counter.current().anchor.mc}, {}, 'd', 'd'),
    block(right, {shard11}, {tx(hash('4'), 1, Status::nonexist, Status::frozen)}, 'f', '7'),
    block(left, {shard11}, {tx(hash('5'), 1, Status::uninit, Status::active)}, 'f', 'f')
  });
  split.next.tips.push_back(tip(right, '7'));
  fails([&] { counter.apply(split); });
  assert(counter.current().anchor.mc.seqno == 3);
  auto merged = id(0, 1, 13, '8');
  auto synthetic_premerge = baseline();
  synthetic_premerge.anchor = split.next;
  auto merge = next(synthetic_premerge, 5, merged, {
    block(id(-1, 1, 5, '8'), {split.next.mc}, {}, 'd', 'd'),
    block(merged, {left, right}, {tx(hash('4'), 2, Status::frozen, Status::nonexist)}, 'f', 'f')
  });
  fails([&] { Counter(synthetic_premerge).apply(merge); });
  std::cout << "accounts fixture OK\n";
}
