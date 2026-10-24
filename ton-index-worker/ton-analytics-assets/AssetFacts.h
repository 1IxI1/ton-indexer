#pragma once

#include "../tondb-scanner/src/assets_analytics/Outcome.h"

#include <cstdint>
#include <string>
#include <vector>

namespace assets_analytics {

struct BatchMeta {
  std::string network, zerostate, calc_version, mc_full_id, mc_state_root_hash;  // zerostate = root hash
  uint32_t mc_gen_utime{0};
  // Full network identity needs BOTH zerostate root and file hash. Trailing
  // aggregate member keeps old six-field initializers source-compatible, but
  // render_batch_json rejects an omitted file hash.
  std::string zerostate_file_hash{};
};

// Offline, immutable address-subset envelope. Sorts observations by wallet address;
// rejects duplicate/empty addresses or invalid batch metadata via std::invalid_argument;
// oversized (>256 KiB) output via std::length_error.
// Never writes a database or certifies network-wide/daily completion.
std::string render_batch_json(const BatchMeta&, const std::vector<Observation>&);

}  // namespace assets_analytics
