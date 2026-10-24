#pragma once

#include "IndexData.h"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace ton_analytics::flow {

// Decimal integers (not floating point, and not machine-sized counters).
// The caller supplies network/zerostate and verifies ancestry and completeness.
struct BlockId {
  int32_t workchain;
  uint64_t shard;
  uint32_t seqno;
  std::string root_hash;
  std::string file_hash;
};

struct ZeroSinkSend {
  BlockId source_block;
  std::string account_hex;
  uint64_t tx_lt;
  std::string tx_hash;
  uint16_t out_msg_index;
  std::string message_hash;
  uint32_t tx_now;
  std::string value_nanoton;
  bool bounce;
  bool bounced;
  // Delivery is NOT inferred from emission. This is not protocol burning.
};

struct BlockFact {
  BlockId id;
  BlockId first_included_by;
  uint32_t gen_utime;
  uint32_t mc_inclusion_utime;
  std::string raw_root_hash;
  std::string tx_fee_augmentation_nanoton;
  std::string import_fee_augmentation_nanoton;
  std::string gross_fees_nanoton;
  std::string created_nanoton;
  std::optional<std::string> burned_nanoton; // null for v1 (no burned field)
  std::string burn_status; // total_from_v2_breakdown_unknown | value_flow_v1_absent
  std::string minted_grams_nanoton; // diagnostic only; NOT added to created
  uint32_t applied_global_version = 0; // per-block predecessor MC config #8
  uint64_t tx_count = 0;
  uint64_t zero_sink_sent_count = 0;
  std::string zero_sink_sent_nanoton;
};

struct Batch {
  BlockId mc_id;
  uint32_t mc_gen_utime = 0;
  std::vector<BlockFact> blocks;
  std::vector<ZeroSinkSend> zero_sink_sends;
};

struct Limits {
  size_t max_blocks = 4096;
  size_t max_accounts_per_block = 250000;
  size_t max_transactions_per_block = 250000;
  size_t max_messages_per_block = 500000;
  size_t max_zero_sink_sends_per_batch = 100000;
};

// Each block may have a DIFFERENT applied config version (e.g. a delayed shard
// across a key block). Resolve from that block's execution predecessor MC state,
// not from the post-state of its including MC; nullopt / unsupported => error.
using AppliedGlobalVersion = std::function<std::optional<uint32_t>(const BlockId&)>;

// All-or-error: throws std::runtime_error (including TL-B/dictionary failures).
// Never reads shard_blocks_ for monetary/event totals; no state/config access.
// Rejects repeated block coordinates even with different hashes. Caller must still
// deduplicate the returned full IDs across MC batches and validate MC ancestry.
Batch extract(const schema::MasterchainBlockDataState& source,
              const AppliedGlobalVersion& applied_version, const Limits& limits = {});

// Small synthetic test seam for counters; not a replacement for raw-BoC tests.
namespace detail {
uint32_t require_applied_global_version(const AppliedGlobalVersion& resolve,
                                        const BlockId& block);
void count_transaction(BlockFact& fact, size_t max_transactions);
void record_zero_sink_send(Batch& batch, BlockFact& fact, ZeroSinkSend send,
                           td::RefInt256 value, td::RefInt256& block_sum,
                           size_t max_batch_sends);
}

} // namespace ton_analytics::flow
