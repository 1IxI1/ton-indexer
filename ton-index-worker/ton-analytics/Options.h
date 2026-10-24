#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace tonstat::runner {
inline constexpr char kVersion[] = "ton-analytics-ndjson-v1";
struct AnchorRequest {
  uint32_t seqno{};
  std::string root, file; // optional for a range, mandatory in an anchor file
};
struct Options {
  std::filesystem::path db, secondary, work;
  std::string network, zero_root, zero_file;
  std::vector<AnchorRequest> anchors;
  uint32_t max_anchors = 4, max_blocks = 256, max_transactions = 100000;
  uint32_t max_aux = 256, max_seconds = 300;
  uint32_t anchor_time_from = 1788220800, anchor_time_to = 1790812800; // September 2026 UTC
  uint64_t max_output_bytes = 64 * 1024 * 1024, accounts_limit = 0;
  bool supply = false, wallet_events = false, nft_candidates = false;
  // Exact options/plan, not primary indexer progress, define this local run.
  std::string scope() const;
};
void require(bool condition, const std::string& reason);
std::string lower(std::string value);
bool hash_hex(const std::string& value);
Options parse_options(const std::vector<std::string>& args);
void validate_paths(Options& options);
} // namespace tonstat::runner
