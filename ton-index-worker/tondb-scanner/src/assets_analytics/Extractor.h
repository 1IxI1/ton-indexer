#pragma once

#include "Outcome.h"
#include "block/block.h"
#include "block/mc-config.h"
#include "vm/cells.h"

#include <memory>
#include <vector>

namespace assets_analytics {

// Trust boundary: caller MUST verify state-update proofs, complete current-tip
// manifest and config extraction against this MC post-state before attesting below.
// We locally check root hashes/shard IDs, NOT proofs or global coverage. No NodeDB I/O.
struct StateRoot {
  ton::BlockIdExt block_id;
  td::Bits256 state_root_hash;
  td::Ref<vm::Cell> root;
  bool caller_attests_state_update_verified{false};
};

struct Anchor {
  std::string network;
  std::string zerostate;
  unsigned gen_utime{0};
  StateRoot mc;
  std::vector<StateRoot> shard_tips;
  bool caller_attests_complete_tip_manifest{false};
  std::shared_ptr<block::ConfigInfo> config;  // extracted from mc.root
  bool caller_attests_config_from_this_mc_root{false};
  // Each record is an independently authenticated external audit of BOTH methods,
  // code versions and the native C7 limitations on this exact anchor/account pair.
  // The extractor cannot create or validate that off-chain analysis itself.
  std::vector<GetterContextAudit> getter_context_audits;
};

struct Budget {
  size_t max_wallets{0};
  size_t max_tip_roots{0};
  size_t max_total_provenance_bytes{0}; // aggregate manifest copies across all observations
};

// Returns exactly one observation per input (including unchanged accounts), in input order.
// Rejects over-limit requests before reading a root. Read-only; no actor, I/O or writer.
td::Result<std::vector<Observation>> observe_wallets(const Anchor& anchor,
                                                       const std::vector<block::StdAddress>& wallets,
                                                       Budget budget);

}  // namespace assets_analytics
