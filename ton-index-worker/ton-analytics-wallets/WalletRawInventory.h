#pragma once

#include "WalletStage.h"

#include <cstddef>
#include <string>

namespace ton_analytics::wallets::raw_inventory {

struct Limits {
  std::size_t max_accounts = 100'000;
  std::size_t max_transactions = 100'000;
  std::size_t max_out_messages = 500'000;
  // Bounds BOTH original BoC cells (before lazy loads) and inventory traversal
  // references, including repeats. No traversal into Block.state_update.
  std::size_t max_cells = 2'000'000;
};

// The *caller* must first verify the FULL block file hash, representation-root
// hash, post-state/update proof and canonical first-inclusion against NodeDB.
// The boolean and proof ID are supplied by that caller, never established here.
// A two-MC diagnostic cannot use this proof to assert lifetime/day coverage.
struct CallerProof {
  ton::BlockIdExt expected_id;
  bool full_file_root_state_verified = false;
  bool first_included_verified = false;
  std::string proof_id;
};

struct Result {
  stage::BlockInventory inventory;
  std::size_t account_count = 0;
  std::size_t out_message_count = 0;
  // Block + BlockInfo + BlockExtra + the AccountBlocks closure, repeated edges
  // included. Excludes unrelated state_update/value_flow/message-descriptor trees.
  std::size_t reachable_cell_references = 0;
  // Echoes an external proof ID for provenance; not a generated attestation.
  std::string caller_proof_id;
};

// No new DB, CH, parser, writer or network access. Reads an already verified
// BlockDataState synchronously while the caller retains BlockData and its root
// (BlockQ owns the lazy BoC decoder). Original BoC header/file hash bound native
// lazy expansion before any load; load errors remain failures. Fully eager
// in-memory sources may omit BoC bytes for backwards compatibility. Rejects
// malformed/over-limit raw dictionaries rather than emitting a partial result.
// The resulting inventory is independent of events::Batch / ParseQuery rows.
// Throws std::invalid_argument on missing/inconsistent evidence, std::length_error
// on caps. Does NOT certify canonical ancestry, zerostate, publication or UTC days.
Result build(const schema::BlockDataState& source, const CallerProof& proof,
             Limits limits = {});

namespace detail {
// Strict native TL-B AccountStatus tag conversion (never cast unchecked bytes).
AccountStatus status(int native_tag);
// Pure predicate AFTER the message's full TL-B type and source were inspected.
// 0=internal, 1=external-out; external-in/unknown is inconsistent in out_msgs.
bool qualifies_outgoing(int kind, bool source_matches_account, bool bounced);
} // namespace detail

} // namespace ton_analytics::wallets::raw_inventory
