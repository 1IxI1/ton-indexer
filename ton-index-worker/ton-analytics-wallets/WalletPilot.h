#pragma once

#include "WalletCliOptions.h"

#include <cstddef>
#include <cstdint>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace ton_analytics::wallets::pilot {

inline constexpr char kCalcVersion[] = "wallets-two-mc-diagnostic-v1";
inline constexpr std::size_t kMaxDiagnosticBytes = 1'000'000;

// Fixed, pre-open resource ceilings. Chief's successful secondary smoke used
// 2.54 GiB RSS / 93.81 s aggregate CPU, so the former 2 GiB / 60 s / 90 s
// limits would kill a bounded domain read. No runtime budget override exists:
// WalletCliOptions rejects extra/unknown flags. NOFILE is set externally.
inline constexpr std::uint64_t kAddressSpaceLimitBytes = 16ull << 30;
inline constexpr unsigned kCpuLimitSeconds = 900;
inline constexpr unsigned kWallLimitSeconds = 300;
inline constexpr unsigned kExternalNofileBudget = 1'048'576;

// Include the NDJSON newline; checked before publishing either of two rows.
inline bool fits_diagnostic(std::size_t already, std::size_t next) {
  return already <= kMaxDiagnosticBytes && next < kMaxDiagnosticBytes - already;
}

// Append context to a native td::Status via move_as_error_prefix(), which
// retains its original error code/type and message. Kept STL-only so failure
// stage names can be regression-tested without opening a NodeDB.
inline std::string failure_stage_prefix(std::string_view stage) {
  return std::string(stage) + ": ";
}

inline std::string mc_failure_stage(std::string_view operation, std::uint32_t seqno) {
  return std::string(operation) + "_mc_seqno_" + std::to_string(seqno);
}

inline bool equal_hex256(std::string_view expected, std::string_view actual) {
  if (expected.size() != 64 || actual.size() != 64) return false;
  for (std::size_t i = 0; i < 64; ++i) {
    const auto lower = [](char c) { return c >= 'A' && c <= 'F' ? char(c - 'A' + 'a') : c; };
    if (lower(expected[i]) != lower(actual[i])) return false;
  }
  return true;
}

// This is a published network identity PIN, not local evidence that MC0 exists
// in NodeDB and not a chain-coverage proof. Never use it for stage::build.
inline bool published_network_pin(const cli::WalletCliOptions& o) {
  if (o.network == "mainnet") {
    return equal_hex256(o.zerostate_root, "17a3a92992aabea785a7a090985a265cd31f323d849da51239737e321fb05569") &&
           equal_hex256(o.zerostate_file, "5e994fcf4d425c0a6ce6a792594b7173205f740a39cd56f537defd28b48a0f6e");
  }
  if (o.network == "testnet") {
    return equal_hex256(o.zerostate_root, "823f81f306ff02694f935cf5021548e3ce2b86b529812af6a12148879e95a128") &&
           equal_hex256(o.zerostate_file, "67e20ac184b9e039a62667acc3f9c00f90f359a76738233379efa47604980ce8");
  }
  return false;
}

// Match BOTH the native TON ErrorCode::notready (651) and the exact LTDB
// message produced by archive-slice.cpp. Other failures are never a fallback.
inline bool external_pin_allowed(const cli::WalletCliOptions& o, int code,
                                 std::string_view message) {
  return o.allow_external_zerostate_pin_diagnostic && published_network_pin(o) &&
         code == 651 && message == "ltdb: block not found";
}

inline bool can_build_stage(bool mc0_local_verified, cli::Scope scope, bool has_previous_anchor) {
  return mc0_local_verified && scope == cli::Scope::masterchain_and_basechain && has_previous_anchor;
}

// Shared with offline contract tests; these flags are unconditional even when
// a locally verified MC0 allows stage/reducer input to be inspected.
inline std::string diagnostic_incompleteness_fields() {
  return ",\"daily_activations\":null,\"cumulative_activations\":null,\"dau\":null,\"mau_30d\":null"
         ",\"metric_reason\":\"no verified lifetime baseline, day frontier or physical writer\""
         ",\"writer_committed\":false,\"publication_ready\":false,\"lifetime_complete\":false";
}

// Set comparison alone hides duplicate references. The production caller
// supplies full BlockIdExt values (including BOTH hashes), not coordinates.
template <class FullId>
bool same_unique_full_ids(const std::vector<FullId>& raw, const std::vector<FullId>& metadata) {
  if (raw.empty() || raw.size() != metadata.size()) return false;
  const std::set<FullId> a(raw.begin(), raw.end()), b(metadata.begin(), metadata.end());
  return a.size() == raw.size() && b.size() == metadata.size() && a == b;
}

// Recheck immediately before opening NodeDB. Does not claim to prevent a
// concurrent filesystem rename: only run on a trusted, quiescent host.
inline void revalidate_paths(const cli::WalletCliOptions& o) {
  const auto root = cli::detail::directory(o.db_root.string(), "db-root");
  const auto work = cli::detail::directory(o.secondary_work_dir.string(), "secondary-work-dir");
  if (root != o.db_root || work != o.secondary_work_dir ||
      cli::detail::inside(root, work) || cli::detail::inside(work, root) ||
      !std::filesystem::is_empty(work)) {
    throw std::invalid_argument("secondary work directory changed, is nonempty or overlaps DB root");
  }
}

// A compile-time approval is necessary but never sufficient: the TON adapter
// must also be deliberately enabled and a secondary-read safety review done.
inline void require_review(bool reviewed, bool adapter) {
  if (!reviewed) throw std::runtime_error("STOP: TON Wallets secondary safety review not approved");
  if (!adapter) throw std::runtime_error("STOP: TON Wallets secondary/ParseQuery adapter unavailable in this build");
}

} // namespace ton_analytics::wallets::pilot
