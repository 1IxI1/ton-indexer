#pragma once

#include "Relationships.h"
#include "td/utils/base64.h" // IndexData.h uses td::base64_encode without including its declaration.
#include "IndexData.h"

#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace tonstat::core {

// A network label alone is not provenance. Both MC zerostate hashes must be
// pinned out of band. This does not establish an MC0-to-anchor chain proof.
struct NetworkPin {
  ton::BlockIdExt zerostate;
};

enum class Status { verified_local_archive, incomplete, error };
enum class Scope { full_snapshot, auxiliary_mc_only };

struct Check {
  std::string code;
  std::string subject;  // full BlockIdExt (or "mc_manifest" / "mc_predecessor")
  std::string observed; // copied digest / ID; never a borrowed cell
};

struct AnchorEvidence {
  Status status{Status::incomplete};
  Scope scope{Scope::full_snapshot};
  // Snapshot integrity and optional adjacent-anchor continuity are distinct.
  bool snapshot_integrity_checked{false};
  Status continuity_status{Status::incomplete};
  std::string continuity_reason{"adjacent_previous_mc_not_supplied"};
  std::vector<Issue> issues;
  std::vector<Check> checks;
  std::string network; // derived from raw MC Block.global_id, not caller input
  NetworkPin pin;
  std::optional<ton::BlockIdExt> mc_state_zerostate;
  bool mc_signatures_checked{false};
  // Local hashes and predecessor continuity are NOT a signature or genesis-chain proof.
  bool cryptographic_zerostate_link_checked{false};
  BlockEvidence mc;
  std::vector<ton::BlockIdExt> mc_predecessors;
  std::vector<ton::BlockIdExt> expected_shard_tips; // raw MC post-state ShardHashes, includes seqno=0
  std::vector<BlockEvidence> shard_tips;
  std::vector<BlockEvidence> first_included; // MC + shard diff; IDs unique within this input
  bool diff_handle_inclusion_checked{false};
  bool diff_exhaustiveness_checked{false}; // requires a separate canonical ancestry walk
  std::optional<ton::BlockIdExt> previous_mc;
  std::optional<td::Bits256> previous_mc_state_root;
};

struct Outcome;

// Keeps copied td::Ref<vm::Cell>/BlockData/handle plus the CellDbReader alive.
// A consumer must retain shared_ptr<MaterializedAnchor>, NOT a naked cell/entry
// reference, across async work. No lazy descendants are serialized here.
class MaterializedAnchor final {
 public:
  const AnchorEvidence& evidence() const { return evidence_; }
  const schema::BlockDataState& mc() const { return snapshot_.shard_blocks_.front(); }
  // Includes independently fetched zero-seqno tips; safe for downstream
  // read-only extractors while this shared_ptr is retained.
  const schema::MasterchainBlockDataState& snapshot() const { return snapshot_; }
  const std::vector<schema::BlockDataState>& first_included() const { return snapshot_.shard_blocks_diff_; }

 private:
  friend struct Outcome;
  friend Outcome verify_anchor(const schema::MasterchainBlockDataState&, const ton::BlockIdExt&,
                               const NetworkPin&, const std::vector<schema::BlockDataState>&,
                               const schema::BlockDataState*, std::shared_ptr<vm::CellDbReader>);
  MaterializedAnchor(AnchorEvidence evidence, const schema::MasterchainBlockDataState& snapshot,
                     const std::vector<schema::BlockDataState>& extra,
                     std::shared_ptr<vm::CellDbReader> reader)
      : evidence_(std::move(evidence)), snapshot_(snapshot), reader_(std::move(reader)) {
    snapshot_.shard_blocks_.insert(snapshot_.shard_blocks_.end(), extra.begin(), extra.end());
  }
  // These refs do not serialize lazy descendants; reader_ keeps them resolvable.
  AnchorEvidence evidence_;
  schema::MasterchainBlockDataState snapshot_;
  std::shared_ptr<vm::CellDbReader> reader_;
};

struct Outcome {
  // Persistent immutable copy: remains available after scanner/parser inputs
  // disappear and cannot be changed through the returned API.
  std::shared_ptr<const AnchorEvidence> evidence;
  // Only non-null on verified result AND with a retained reader lease. A caller
  // without a reader may use copied evidence but cannot safely retain lazy cells.
  std::shared_ptr<const MaterializedAnchor> view;
};

// No DB calls. expected_mc must be the externally selected FULL block ID.
// extra_tips are loaded separately by full ID for nonzero tips. Seqno-zero
// tips require a distinct zerostate BoC/state verifier, NOT this block decoder;
// their presence currently makes the result explicitly incomplete.
// previous is a separately loaded adjacent MC block AND state, checked anew
// against its own original BoC/full ID; no caller-supplied prior hash/boolean.
Outcome verify_anchor(const schema::MasterchainBlockDataState& input,
                      const ton::BlockIdExt& expected_mc, const NetworkPin& pin,
                      const std::vector<schema::BlockDataState>& extra_tips = {},
                      const schema::BlockDataState* previous = nullptr,
                      std::shared_ptr<vm::CellDbReader> reader = nullptr);

// For separately loaded historical MC states (e.g. Supply processed_upto or
// Validators election states). Same raw full-ID/BoC/update checks; this is NOT
// an assertion that the auxiliary state is ancestral to the selected anchor.
std::shared_ptr<const AnchorEvidence> verify_auxiliary_mc(
    const schema::BlockDataState& entry, const ton::BlockIdExt& expected_mc, const NetworkPin& pin);

namespace testing {
// Production decoder seam: validates the exotic Merkle update and returns its
// encoded old/new hashes. Throws on missing, ordinary or invalid update cells.
std::pair<td::Bits256, td::Bits256> state_update_hashes(td::Ref<vm::Cell> update);
// The exact bounded TL-B validator used before ShardConfig enumeration.
// This alone does not prove a manifest belongs to an MC anchor.
bool valid_shard_hashes(td::Ref<vm::CellSlice> encoded);
}

} // namespace tonstat::core
