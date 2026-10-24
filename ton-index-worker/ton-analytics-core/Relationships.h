#pragma once

#include "ton/ton-types.h"
#include "td/utils/Slice.h"

#include <optional>
#include <string>
#include <vector>

namespace tonstat::core {
struct Issue {
  std::string code;
  std::string detail;
};

struct BlockEvidence {
  ton::BlockIdExt id;
  td::Bits256 state_root;
  td::Bits256 state_update_old;
  td::Bits256 state_update_new;
  int32_t global_id{};
  uint32_t gen_utime{};
};

namespace testing {
// Pure relationship checker, called only AFTER native raw decoding in the
// production verifier. Synthetic inputs do not authenticate any archive.
std::vector<Issue> check_block_hashes(td::Slice original_boc, const ton::BlockIdExt& id,
    td::Bits256 actual_block_root, td::Bits256 raw_update_new, td::Bits256 actual_state_root);

// Fixed MC0 identities from ton.org/{global,testnet-global}.config.json.
// Unknown global IDs cannot be labelled mainnet/testnet by a caller's pin.
std::optional<ton::BlockIdExt> trusted_mc0(int32_t global_id);
std::vector<Issue> check_network_pin(int32_t global_id, const ton::BlockIdExt& pin,
                                    const ton::BlockIdExt& decoded_mc0);

std::vector<Issue> check_relationships(const BlockEvidence& mc,
    const std::vector<ton::BlockIdExt>& raw_predecessors,
    const std::vector<ton::BlockIdExt>& expected_tips,
    const std::vector<BlockEvidence>& loaded_tips,
    const std::vector<BlockEvidence>& included,
    const std::optional<BlockEvidence>& previous);
} // namespace testing
} // namespace tonstat::core
