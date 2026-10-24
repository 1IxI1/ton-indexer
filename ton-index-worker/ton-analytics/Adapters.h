#pragma once
#include "Serialization.h"
#include "../ton-analytics-core/AnchorEvidence.h"
#include "../tondb-scanner/src/analytics/validators/ValidatorStage.h"

namespace tonstat::runner {
// Copies the typed anchor from run_verified_mc; never promotes its status.
analytics::validators::stage::Input validator_input(const analytics::validators::stage::Output& verified_mc);
// Pure boundary join. Production supplies two native-verified MC outputs and
// observations decoded from those states, plus Core's adjacent-state evidence.
// Synthetic metadata passed here is only suitable for tests, not archive proof.
std::optional<analytics::validators::stage::ElectionBoundary> validator_boundary(
    const tonstat::core::AnchorEvidence& adjacent,
    const analytics::validators::stage::Input& current,
    const analytics::validators::stage::Input& previous,
    const std::optional<td::Bits256>& previous_config36,
    const analytics::validators::election::Observation& current_observation,
    const analytics::validators::election::Observation& previous_observation);
std::string write_validators(Rows& rows, const analytics::validators::stage::Output& output);
std::string validators(Rows& rows, const schema::MasterchainBlockDataState& data,
                const tonstat::core::AnchorEvidence& evidence,
                const schema::BlockDataState* previous = nullptr);
void accounts_sample(Rows& rows, const tonstat::core::MaterializedAnchor& view, const Options& options);
void parsed_events(Rows& rows, const ParsedBlock& parsed, const ton_analytics::flow::Batch& flow,
                   const Options& options);
} // namespace tonstat::runner
