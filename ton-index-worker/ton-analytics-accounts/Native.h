#pragma once

#include "Accounts.h"
#include "IndexData.h"

namespace tonstat::accounts {

// Read-only: no DbScanner ownership, NodeDB writes, CH writer or scheduling.
// `limit` is the maximum number of dictionary entries visited, not a memory cap
// on the caller's already-fetched state. Only an explicitly approved full run
// may set allow_full=true; limit is still enforced and truncation is incomplete.
Snapshot scan_snapshot(const schema::MasterchainBlockDataState& input,
                       const std::string& network, const std::string& zerostate,
                       std::uint64_t limit, bool allow_full = false, Caps caps = {});

// Caller supplies previous verified anchor; adapter verifies raw block ancestry,
// state-update hashes, exact first-included diff and final MC shard tip manifest.
// Never use ParsedBlock.account_states_: that may silently skip failed cell reads.
Step decode_step(const schema::MasterchainBlockDataState& input,
                 const Anchor& previous, const std::string& network,
                 const std::string& zerostate, Caps caps = {});

} // namespace tonstat::accounts
