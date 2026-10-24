#ifdef NDEBUG
#undef NDEBUG // Assertions are the test oracle even in RelWithDebInfo builds.
#endif
#include "Relationships.h"
#include "common/checksum.h"
#include <cassert>
#include <iostream>
#include <string>

using namespace tonstat::core;

namespace {
td::Bits256 hash(const char* text) { return td::sha256_bits256(td::Slice(text)); }

ton::BlockIdExt id(int wc, uint64_t shard, uint32_t seqno, const char* label) {
  const auto base = std::string(label);
  return {wc, shard, seqno, td::sha256_bits256(base + "-root"),
          td::sha256_bits256(base + "-file")};
}

BlockEvidence block(ton::BlockIdExt id, const char* root, const char* old, int global = -239) {
  auto state = hash(root);
  return {id, state, hash(old), state, global, 100};
}

bool has(const std::vector<Issue>& issues, const std::string& code) {
  for (const auto& i : issues) if (i.code == code) return true;
  return false;
}

void projection_cases() {
  const auto prev_id = id(-1, ton::shardIdAll, 10, "prev");
  const auto mc_id = id(-1, ton::shardIdAll, 11, "mc");
  const auto tip_zero = id(0, ton::shardIdAll, 0, "zero");
  const auto tip_one = id(0, ton::shardIdAll, 5, "one");
  const auto mid = id(0, ton::shardIdAll, 4, "intermediate");
  const auto previous = block(prev_id, "prior-state", "older");
  auto mc = block(mc_id, "mc-post", "prior-state");
  auto tips = std::vector<BlockEvidence>{block(tip_zero, "zero-post", "zero-old"),
                                         block(tip_one, "one-post", "one-old")};
  auto diff = std::vector<BlockEvidence>{mc, block(mid, "mid-post", "mid-old")};
  auto expected = std::vector<ton::BlockIdExt>{tip_zero, tip_one};
  auto check = [&](std::optional<ton::BlockIdExt> predecessor = std::nullopt,
                   std::optional<BlockEvidence> prior = std::nullopt) {
    return testing::check_relationships(mc, {predecessor.value_or(prev_id)}, expected, tips, diff,
                                        prior.value_or(previous));
  };
  assert(check().empty());
  assert(testing::check_relationships(mc, {prev_id}, expected, tips, diff, std::nullopt).empty());
  tips.erase(tips.begin());
  assert(has(check(), "missing_tip")); // zero-seqno omission is never silently accepted
  tips.insert(tips.begin(), block(tip_zero, "zero-post", "zero-old"));
  tips.push_back(tips.front());
  assert(has(check(), "duplicate_loaded_tip"));
  tips.pop_back();
  expected.push_back(tip_zero);
  assert(has(check(), "duplicate_mc_manifest_tip"));
  expected.pop_back();
  tips[1].id = id(0, ton::shardIdAll, 5, "wrong-file-and-root");
  assert(has(check(), "missing_tip") && has(check(), "unexpected_tip"));
  tips[1].id = tip_one;
  tips[1].global_id = -3;
  assert(has(check(), "tip_global_id_mismatch"));
  tips[1].global_id = -239;
  tips[0].state_update_new = hash("bad-update");
  assert(has(check(), "tip_update_new_mismatch"));
  tips[0].state_update_new = tips[0].state_root;

  assert(has(check(id(-1, ton::shardIdAll, 10, "wrong-hash")), "adjacent_mc_full_id_mismatch"));
  assert(has(testing::check_relationships(mc, {}, expected, tips, diff, previous), "invalid_mc_predecessor"));
  assert(has(testing::check_relationships(mc, {prev_id, prev_id}, expected, tips, diff, previous),
             "invalid_mc_predecessor"));
  auto incorrect_prior = previous;
  incorrect_prior.state_root = hash("wrong-prior-state");
  assert(has(check(prev_id, incorrect_prior), "adjacent_mc_previous_state_hash_mismatch"));
  incorrect_prior = previous;
  incorrect_prior.id = id(-1, ton::shardIdAll, 8, "gap");
  assert(has(check(prev_id, incorrect_prior), "adjacent_mc_full_id_mismatch"));
  mc.state_update_new = hash("wrong-mc-update");
  assert(has(check(), "mc_update_new_mismatch"));
  mc.state_update_new = mc.state_root;

  diff.push_back(diff.front());
  assert(has(check(), "duplicate_diff_block"));
  diff.pop_back();
  diff[0] = block(mid, "mid-post", "mid-old");
  assert(has(check(), "missing_mc_in_diff") && has(check(), "duplicate_diff_block"));
  diff[0] = mc;
  diff[0].state_root = hash("wrong-mc-diff-root");
  assert(has(check(), "diff_mc_post_state_mismatch"));
  diff[0] = mc;
  diff[1].global_id = -3;
  assert(has(check(), "diff_global_id_mismatch"));
  diff[1].global_id = -239;
  diff[1].state_update_new = hash("bad-diff-update");
  assert(has(check(), "diff_update_new_mismatch"));
  diff[1].state_update_new = diff[1].state_root;
  assert(check().empty());
}

void block_hash_cases() {
  const auto original = std::string("synthetic original block BoC bytes");
  auto block_id = id(-1, ton::shardIdAll, 3, "block");
  block_id.file_hash = td::sha256_bits256(original);
  const auto state = hash("post-state");
  auto check = [&](const std::string& bytes, td::Bits256 block_root, td::Bits256 new_hash,
                   td::Bits256 state_root) {
    return testing::check_block_hashes(td::Slice(bytes), block_id, block_root, new_hash, state_root);
  };
  assert(check(original, block_id.root_hash, state, state).empty());
  assert(has(check("mutated original BoC", block_id.root_hash, state, state), "file_hash_mismatch"));
  assert(has(check("", block_id.root_hash, state, state), "file_hash_mismatch"));
  assert(has(check(original, hash("wrong block root"), state, state), "block_root_mismatch"));
  assert(has(check(original, block_id.root_hash, hash("wrong update"), state),
             "state_update_new_mismatch"));
}

void network_pin_cases() {
  const auto mainnet = testing::trusted_mc0(-239);
  const auto testnet = testing::trusted_mc0(-3);
  assert(mainnet && testnet && *mainnet != *testnet);
  assert(!testing::trusted_mc0(0));
  assert(testing::check_network_pin(-239, *mainnet, *mainnet).empty());
  assert(testing::check_network_pin(-3, *testnet, *testnet).empty());
  assert(has(testing::check_network_pin(-239, *testnet, *mainnet), "untrusted_network_zerostate"));
  assert(has(testing::check_network_pin(-239, *mainnet, *testnet), "mc_state_zerostate_mismatch"));
  assert(has(testing::check_network_pin(-239, id(-1, ton::shardIdAll, 0, "invented"), *mainnet),
             "untrusted_network_zerostate"));
  assert(has(testing::check_network_pin(123, *mainnet, *mainnet), "unknown_network_global_id"));
}

} // namespace

int main() {
  projection_cases();
  block_hash_cases();
  network_pin_cases();
  std::cout << "AnchorEvidence synthetic checks passed\n";
}
