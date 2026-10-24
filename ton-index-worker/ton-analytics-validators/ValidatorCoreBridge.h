#pragma once

#include "../ton-analytics-core/AnchorEvidence.h"
#include "../tondb-scanner/src/analytics/validators/ValidatorStage.h"

#include <memory>
#include <vector>

namespace tonstat::validators {

struct CoreStageOutcome {
  analytics::validators::stage::Output stage;
  // Immutable, copied core provenance. Never contains a borrowed Cell or reader.
  // Null only when the scanner supplied no MC entry to verify.
  std::shared_ptr<const tonstat::core::AnchorEvidence> core;
};

// expected_full_id and pin MUST be supplied independently of loaded. This is
// synchronous: loaded and its CellDbReader must live through this entire call.
// Auxiliary MC verification does not prove the anchor's shard-tip snapshot,
// adjacent MC continuity, consensus signatures, or an election boundary.
CoreStageOutcome run_verified_mc(const schema::MasterchainBlockDataState& loaded,
                                 const ton::BlockIdExt& expected_full_id,
                                 const tonstat::core::NetworkPin& pin,
                                 const std::vector<td::Bits256>& allowed_codes);

namespace testing {
// PURE SYNTHETIC MAPPING SEAM. A caller can forge AnchorEvidence here: this
// function CANNOT authenticate a BoC or MC state and MUST NOT be used by the
// production entrypoint. Only run_verified_mc invokes the native core verifier.
analytics::validators::stage::Input map_synthetic_core(
    const tonstat::core::AnchorEvidence& evidence, const ton::BlockIdExt& expected_full_id,
    const tonstat::core::NetworkPin& pin, const std::vector<td::Bits256>& allowed_codes);
}  // namespace testing

}  // namespace tonstat::validators
