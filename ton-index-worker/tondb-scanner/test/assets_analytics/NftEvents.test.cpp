// Offline decision/guard tests: no DB, no generated TON headers, no native
// linkage. NftEvents.native.test.cpp separately exercises the production
// DataParser transaction/message helpers and NftEvents.cpp using generated native
// cells. Its pinned native build hook is NftEvents.native.cmake; passing this
// header-only suite says nothing about the native fixture's execution.
#include "../../src/assets_analytics/NftEvents.h"

#include <algorithm>
#include <cstdlib>
#include <iostream>
#include <limits>

using namespace assets_analytics::nft_events;

static void require(bool condition, const char* message) {
  if (!condition) {
    std::cerr << message << '\n';
    std::abort();
  }
}

int main() {
  const std::string uppercase(64, 'A');
  const std::string lowercase(64, 'a');
  require(canonical_account_address(0, uppercase) == "0:" + lowercase,
          "native uppercase raw account must match lowercase reviewed item");
  require(canonical_account_address(0, uppercase) == canonical_account_address(0, lowercase),
          "case normalization must not create a false negative");
  require(canonical_account_address(-1, uppercase) == "-1:" + lowercase &&
              canonical_account_address(-1, uppercase) != canonical_account_address(0, lowercase),
          "same account bits in different workchains must never alias");
  require(!canonical_account_address(0, "AAAA") &&
              !canonical_account_address(0, std::string(63, 'A') + "G"),
          "short or nonhex raw account must fail closed");

  require(decide({Status::uninit, Status::active, true, true}) ==
              Decision::possible_first_initialization, "deploy lead");
  require(decide({Status::nonexist, Status::active, true, true}) ==
              Decision::possible_first_initialization, "first activation lead");
  require(decide({Status::active, Status::active, true, true}) ==
              Decision::possible_first_initialization, "already deployed item may initialize later");
  require(decide({Status::active, Status::active, true, false}) == Decision::not_candidate,
          "unchanged active state is not a lead");
  require(decide({Status::uninit, Status::active, false, true}) == Decision::not_candidate,
          "failed/bounced transaction is not a lead");
  require(decide({Status::active, Status::nonexist, true, true}) == Decision::not_candidate,
          "destroy is not initialization evidence");
  require(decide({Status::uninit, Status::uninit, true, true}) == Decision::not_candidate,
          "non-deploy funding is not a mint");

  const BlockId mc{-1, std::numeric_limits<int64_t>::min(), 7, "mc-root", "mc-file"};
  const BlockId shard{0, std::numeric_limits<int64_t>::min(), 9, "sh-root", "sh-file"};
  const Budget cap{2, 3, 3, 1024};
  require(valid_diff_layout(mc, {mc, shard}, {mc, shard}, cap), "MC+new shard accepted");
  require(!valid_diff_layout(mc, {mc, shard}, {mc, mc}, cap), "parsed/diff mismatch");
  require(!valid_diff_layout(mc, {mc, shard, shard}, {mc, shard, shard}, {3, 3, 3, 1024}),
          "duplicate tip must not become a second event");
  require(!valid_diff_layout(mc, {shard, mc}, {shard, mc}, cap), "explicit MC first");
  require(!valid_diff_layout(mc, {mc, shard}, {mc}, cap), "missing diff block");
  require(!valid_diff_layout(mc, {mc, shard}, {mc, shard}, {1, 3, 3, 1024}),
          "block cap fails closed");
  require(!valid_diff_layout({-1, mc.shard, mc.seqno, "", mc.file_hash}, {mc}, {mc}, cap),
          "missing MC hash fails closed");

  // Two transactions for the SAME item in one block: deploy without item init,
  // then a separate active->active initialization attempt. Preserve both leads;
  // the parser's final post-state alone would lose the first transaction.
  OrderedTx deploy{"0:item", "txA", 101, 0, "earlier", "state0", "state1",
                   Status::uninit, Status::active};
  OrderedTx init{"0:item", "txB", 103, 101, "txA", "state1", "state2",
                 Status::active, Status::active};
  require(contiguous(deploy, init), "same-account deploy-then-init linkage");
  require(decide({deploy.before, deploy.after, true, true}) == Decision::possible_first_initialization &&
          decide({init.before, init.after, true, true}) == Decision::possible_first_initialization,
          "retain both leads, do not deduplicate by account");
  auto missing_state = init;
  missing_state.before_hash.clear();
  require(!contiguous(deploy, missing_state), "missing intermediate state hash");
  auto wrong_prev = init;
  wrong_prev.prev_hash = "unrelated";
  require(!contiguous(deploy, wrong_prev), "broken predecessor transaction");
  auto reversed = init;
  reversed.lt = 100;
  require(!contiguous(deploy, reversed), "invalid ordering");

  Candidate later, earlier;
  later.lt = 103; later.account = "0:item"; later.transaction_hash = "txB";
  earlier.lt = 101; earlier.account = "0:item"; earlier.transaction_hash = "txA";
  std::vector<Candidate> leads{later, earlier};
  std::sort(leads.begin(), leads.end(), candidate_less);
  require(leads[0].transaction_hash == "txA" && leads[1].transaction_hash == "txB",
          "stable ascending LT ordering");
  size_t examined = 0;
  require(bounded_count(2, examined, 3) && examined == 2, "first two tx within cap");
  require(!bounded_count(2, examined, 3) && examined == 2, "tx cap is atomic");
  size_t candidate_count = 0;
  require(bounded_count(2, candidate_count, 2) &&
          !bounded_count(1, candidate_count, 2) && candidate_count == 2,
          "candidate cap cannot silently truncate leads");
  size_t evidence = 32;
  require(!bounded_add(33, evidence, 64) && evidence == 32, "byte cap atomic");
  require(!bounded_add(std::numeric_limits<size_t>::max(), evidence, 64), "no size overflow");
  require(!Result::minted_verified && !Result::lifetime_complete,
          "neither first activation nor two leads prove a lifetime minted count");
  std::cout << "NftEvents offline decision/guard tests PASS\n";
}
