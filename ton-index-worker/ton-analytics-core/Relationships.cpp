#include "Relationships.h"

#include "common/checksum.h"
#include <cstdint>
#include <set>

namespace tonstat::core::testing {
namespace {
bool valid_mc(const ton::BlockIdExt& id) {
  return id.is_masterchain() && id.is_valid_full() && id.id.shard == ton::shardIdAll;
}
} // namespace

std::vector<Issue> check_block_hashes(td::Slice original_boc, const ton::BlockIdExt& id,
    td::Bits256 actual_block_root, td::Bits256 raw_update_new, td::Bits256 actual_state_root) {
  std::vector<Issue> issues;
  if (original_boc.empty() || td::sha256_bits256(original_boc) != id.file_hash)
    issues.push_back({"file_hash_mismatch", id.to_str()});
  if (actual_block_root != id.root_hash)
    issues.push_back({"block_root_mismatch", id.to_str()});
  if (raw_update_new != actual_state_root)
    issues.push_back({"state_update_new_mismatch", id.to_str()});
  return issues;
}

std::optional<ton::BlockIdExt> trusted_mc0(int32_t global_id) {
  const char* root = nullptr;
  const char* file = nullptr;
  if (global_id == -239) {
    root = "17a3a92992aabea785a7a090985a265cd31f323d849da51239737e321fb05569";
    file = "5e994fcf4d425c0a6ce6a792594b7173205f740a39cd56f537defd28b48a0f6e";
  } else if (global_id == -3) {
    root = "823f81f306ff02694f935cf5021548e3ce2b86b529812af6a12148879e95a128";
    file = "67e20ac184b9e039a62667acc3f9c00f90f359a76738233379efa47604980ce8";
  } else {
    return std::nullopt;
  }
  td::Bits256 root_hash, file_hash;
  if (root_hash.from_hex(td::Slice(root)) != 256 || file_hash.from_hex(td::Slice(file)) != 256)
    return std::nullopt;
  return ton::BlockIdExt{ton::masterchainId, ton::shardIdAll, 0, root_hash, file_hash};
}

std::vector<Issue> check_network_pin(int32_t global_id, const ton::BlockIdExt& pin,
                                     const ton::BlockIdExt& decoded_mc0) {
  const auto trusted = trusted_mc0(global_id);
  if (!trusted) return {{"unknown_network_global_id", std::to_string(global_id)}};
  std::vector<Issue> result;
  if (pin != *trusted) result.push_back({"untrusted_network_zerostate", pin.to_str()});
  if (decoded_mc0 != *trusted) result.push_back({"mc_state_zerostate_mismatch", decoded_mc0.to_str()});
  return result;
}

std::vector<Issue> check_relationships(const BlockEvidence& mc,
    const std::vector<ton::BlockIdExt>& raw_predecessors,
    const std::vector<ton::BlockIdExt>& expected_tips,
    const std::vector<BlockEvidence>& loaded_tips,
    const std::vector<BlockEvidence>& included,
    const std::optional<BlockEvidence>& previous) {
  std::vector<Issue> problems;
  auto add = [&](const char* code, const std::string& detail) { problems.push_back({code, detail}); };
  if (!valid_mc(mc.id)) add("invalid_mc_id", mc.id.to_str());
  if (mc.state_root != mc.state_update_new) add("mc_update_new_mismatch", mc.id.to_str());
  if (raw_predecessors.size() != 1 || !valid_mc(raw_predecessors.front()))
    add("invalid_mc_predecessor", mc.id.to_str());
  if (previous) {
    if (!valid_mc(previous->id) || previous->global_id != mc.global_id ||
        previous->id.id.seqno == UINT32_MAX || mc.id.id.seqno == 0 ||
        previous->id.id.seqno + 1 != mc.id.id.seqno ||
        raw_predecessors.size() != 1 || raw_predecessors[0] != previous->id)
      add("adjacent_mc_full_id_mismatch", mc.id.to_str());
    if (mc.state_update_old != previous->state_root)
      add("adjacent_mc_previous_state_hash_mismatch", mc.id.to_str());
  }
  std::set<ton::BlockIdExt> expected, actual, diff;
  for (const auto& id : expected_tips) {
    if (!id.is_valid_full() || id.is_masterchain()) add("invalid_expected_tip_id", id.to_str());
    if (!expected.insert(id).second) add("duplicate_mc_manifest_tip", id.to_str());
  }
  for (const auto& tip : loaded_tips) {
    if (!actual.insert(tip.id).second) add("duplicate_loaded_tip", tip.id.to_str());
    if (tip.global_id != mc.global_id) add("tip_global_id_mismatch", tip.id.to_str());
    if (tip.state_root != tip.state_update_new) add("tip_update_new_mismatch", tip.id.to_str());
  }
  for (const auto& id : expected) if (!actual.count(id)) add("missing_tip", id.to_str());
  for (const auto& id : actual) if (!expected.count(id)) add("unexpected_tip", id.to_str());
  for (const auto& block : included) {
    if (!diff.insert(block.id).second) add("duplicate_diff_block", block.id.to_str());
    if (block.global_id != mc.global_id) add("diff_global_id_mismatch", block.id.to_str());
    if (block.state_root != block.state_update_new) add("diff_update_new_mismatch", block.id.to_str());
    if (block.id == mc.id && block.state_root != mc.state_root)
      add("diff_mc_post_state_mismatch", block.id.to_str());
  }
  if (!diff.count(mc.id)) add("missing_mc_in_diff", mc.id.to_str());
  // Scanner's diff is NOT independently proven exhaustive/first-included here.
  return problems;
}
} // namespace tonstat::core::testing
