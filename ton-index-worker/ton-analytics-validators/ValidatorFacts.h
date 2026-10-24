#pragma once

#include "../tondb-scanner/src/analytics/validators/ValidatorStage.h"

#include <string>

namespace tonstat::validators {

// One bounded, newline-free JSON record per stage output. The returned record
// is producer evidence only, never a writer receipt or publication certificate.
// Invalid/contradictory input throws std::invalid_argument; oversized input or
// output throws std::length_error. No partial record is returned on failure.
std::string render_batch_json(const analytics::validators::stage::Output& out);

}  // namespace tonstat::validators
