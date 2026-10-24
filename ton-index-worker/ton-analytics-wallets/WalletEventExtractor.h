#pragma once

#include "td/utils/base64.h" // IndexData.h uses td::base64_encode in inline formatters.
#include "IndexData.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace ton_analytics::wallets::events {

inline constexpr char kRegistrySha256[] = "fc96280e446129a605659a022311bba1d0d6bef9a03960be77c86a259dc876f9";

struct BlockId {
  int32_t workchain;
  int64_t shard;
  uint32_t seqno;
  std::string root_hash;  // base64, as in schema::Block
  std::string file_hash;
};

enum class Resolution { resolved, proved_nonexist, unavailable, unsupported, replay_error };
enum class Classification { included_wallet, excluded_code, outside_registry, pending };
enum class CodeUse { execution, post_state };

struct CodeEvidence {
  Resolution resolution = Resolution::unavailable;
  std::optional<td::Bits256> code_hash;
  td::Bits256 state_hash;  // pre/post HASH_UPDATE endpoint; applied init uses post as tx context
  std::string source;      // e.g. verified_pre_state, replay_checked, applied_init
  bool verified = false;  // caller attests address, state hash, code and tx/context checks
};

// Implementations must inspect the specific tx and requested endpoint (pre for execution,
// committed post for post_state); never return latest-account code or unverified replay.
// A deployment's execution code can instead be decoded locally from its applied StateInit.
class VerifiedCodeResolver {
 public:
  virtual ~VerifiedCodeResolver() = default;
  virtual CodeEvidence resolve(const schema::Transaction& tx, CodeUse use) = 0;
};

// Read-only resolver over the reader ALREADY attached to ParsedBlock. No connection
// opening or latest-state lookup. Keep it alive only during synchronous extraction.
class CellDbVerifiedResolver final : public VerifiedCodeResolver {
 public:
  explicit CellDbVerifiedResolver(std::shared_ptr<vm::CellDbReader> reader);
  CodeEvidence resolve(const schema::Transaction& tx, CodeUse use) override;

 private:
  std::shared_ptr<vm::CellDbReader> reader_;
};

struct CodeFact {
  Resolution resolution = Resolution::unavailable;
  Classification classification = Classification::pending;
  std::optional<std::string> code_hash_hex;
  std::optional<std::string> wallet_type_id;
  std::string source;
};

struct TxId {
  std::string account; // raw workchain:hex
  uint64_t lt;
  std::string hash_hex;
  uint32_t now;
  uint32_t utc_day_start;
  BlockId mc;
  BlockId shard; // equals mc for a masterchain transaction
  std::string pre_state_hash_hex;  // this tx's native HASH_UPDATE.old_hash (Account cell)
  std::string post_state_hash_hex; // this tx's native HASH_UPDATE.new_hash (Account cell)
};

struct ActiveWitness {
  TxId tx;
  schema::AccountStatus orig_status;
  schema::AccountStatus end_status;
  std::string post_state_hash_hex;
  bool activation_candidate; // uninit -> active; lifetime firstness is NOT decided here
  CodeFact post_code;         // pending if the committed post code is unavailable
};

struct QualifyingSend {
  TxId tx;                    // ONE entry per account/tx/day, not per message
  std::string message_hash_hex; // first qualifying out_msg in transaction order
  CodeFact execution_code;   // pre-state or proven applied deployment, NEVER post-code
};

struct Batch {
  BlockId mc;
  std::string registry_sha256 = kRegistrySha256;
  std::vector<BlockId> included_blocks;
  std::vector<ActiveWitness> active_witnesses;
  std::vector<QualifyingSend> sends;
  size_t pending_post_codes = 0;
  size_t pending_execution_codes = 0;
};

// Pure, read-only: no DB/network access, writes or lifetime/day publication decisions.
// The parsed entry point checks blocks_ against shard_blocks_diff_ (NOT shard_blocks_).
// The lower-level entry point is for an already verified first-included block list;
// caller MUST attest MC ancestry/inclusion and preserve ParsedBlock/cells through call.
Batch extract(const ParsedBlock& parsed, VerifiedCodeResolver& resolver);
Batch extract(const ParsedBlock& parsed); // constructs a CellDbVerifiedResolver from parsed.cell_db_reader_
Batch extract_included(const std::vector<schema::Block>& first_included, const BlockId& mc,
                       VerifiedCodeResolver& resolver,
                       const std::vector<schema::AccountState>& states = {});

// Registry lookup is versioned by kRegistrySha256; an unknown hash is NOT evidence
// that an account has never been a wallet. Excluded hashes are deliberately not members.
CodeFact classify(const CodeEvidence& evidence);

} // namespace ton_analytics::wallets::events
