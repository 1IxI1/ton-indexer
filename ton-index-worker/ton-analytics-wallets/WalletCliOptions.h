#pragma once

#include <algorithm>
#include <charconv>
#include <cstdint>
#include <filesystem>
#include <iterator>
#include <limits>
#include <map>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace ton_analytics::wallets::cli {

enum class Scope { masterchain_only, masterchain_and_basechain };

struct WalletCliOptions {
  std::string network;
  std::string zerostate_root;
  std::string zerostate_file;
  std::filesystem::path db_root;
  std::filesystem::path secondary_work_dir;
  std::uint32_t from = 0;
  std::uint32_t to = 0;
  std::size_t max_tip_roots = 0;    // Across both MC anchors; abort, never truncate.
  std::size_t max_transactions = 0; // Across the entire two-anchor run.
  std::size_t max_blocks = 0;       // Across the entire two-anchor run.
  Scope scope = Scope::masterchain_only;
  bool allow_external_zerostate_pin_diagnostic = false;
};

namespace detail {

inline bool hex256(std::string_view s) {
  return s.size() == 64 && std::all_of(s.begin(), s.end(), [](char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
           (c >= 'A' && c <= 'F');
  });
}

inline std::uint32_t decimal(std::string_view text, const char* field,
                             std::uint32_t maximum = std::numeric_limits<std::uint32_t>::max()) {
  if (text.empty()) throw std::invalid_argument(std::string("invalid ") + field);
  std::uint32_t out = 0;
  const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), out);
  if (error != std::errc{} || end != text.data() + text.size() || out == 0 || out > maximum) {
    throw std::invalid_argument(std::string("invalid or out-of-range ") + field);
  }
  return out;
}

inline bool inside(const std::filesystem::path& child, const std::filesystem::path& parent) {
  auto c = child.begin();
  for (auto p = parent.begin(); p != parent.end(); ++p, ++c) {
    if (c == child.end() || *c != *p) return false;
  }
  return true; // Includes equality, deliberately.
}

inline std::filesystem::path directory(const std::string& name, const char* field) {
  namespace fs = std::filesystem;
  const fs::path path(name);
  if (name.empty() || !path.is_absolute()) {
    throw std::invalid_argument(std::string(field) + " must be an absolute directory");
  }
  // Require the CALLER to provide the actual canonical spelling; do not silently
  // normalize .., ./, repeated slashes, a symlinked ancestor or a symlinked leaf.
  // This is a pre-open check, NOT a defense against subsequent filesystem races.
  const auto canonical = fs::canonical(path); // Must already exist.
  if (name != canonical.string() || !fs::is_directory(canonical)) {
    throw std::invalid_argument(std::string(field) + " must be an existing canonical directory");
  }
  for (fs::path prefix; const auto& part : path) {
    prefix /= part;
    if (fs::is_symlink(fs::symlink_status(prefix))) {
      throw std::invalid_argument(std::string(field) + " must not contain symlinks");
    }
  }
  return canonical;
}

} // namespace detail

// Parse and validate BEFORE any DB open. There is intentionally no readonly or
// primary fallback, connection string, password, CH endpoint or output target.
// The future adapter must use ONLY dbs_secondary and must revalidate directory
// identities at the point of opening (TOCTOU), enforce every cap at runtime,
// and fail closed on missing/incomplete tips, blocks or transactions.
// No live NodeDB run is authorized until TON secondary + GC pass independent review.
inline WalletCliOptions parse_cli(const std::vector<std::string>& args) {
  constexpr std::string_view flag = "--secondary-opt-in";
  constexpr std::string_view diagnostic_flag = "--allow-external-zerostate-pin-diagnostic";
  constexpr std::string_view keys[] = {
      "--network", "--zerostate-root", "--zerostate-file", "--db-root",
      "--secondary-work-dir", "--from", "--to", "--max-tip-roots",
      "--max-transactions", "--max-blocks", "--scope"};
  if (args.size() > 2 * std::size(keys) + 2) throw std::invalid_argument("too many CLI arguments");

  std::map<std::string, std::string> values;
  bool opted_in = false;
  bool external_pin = false;
  for (std::size_t i = 0; i < args.size(); ++i) {
    const auto& key = args[i];
    if (key.size() > 4096 || key.find('\0') != std::string::npos) {
      throw std::invalid_argument("invalid CLI argument");
    }
    if (key == flag) {
      if (opted_in) throw std::invalid_argument("duplicate secondary opt-in");
      opted_in = true;
      continue;
    }
    if (key == diagnostic_flag) {
      if (external_pin) throw std::invalid_argument("duplicate external zerostate diagnostic opt-in");
      external_pin = true;
      continue;
    }
    if (std::find(std::begin(keys), std::end(keys), key) == std::end(keys) || values.contains(key)) {
      throw std::invalid_argument("unknown or duplicate option");
    }
    if (++i == args.size() || args[i].empty() || args[i].size() > 4096 ||
        args[i].find('\0') != std::string::npos || args[i].starts_with("--")) {
      throw std::invalid_argument("missing or invalid option value");
    }
    values.emplace(key, args[i]);
  }
  if (!opted_in || values.size() != std::size(keys)) {
    throw std::invalid_argument("explicit secondary opt-in and every required option are mandatory");
  }

  WalletCliOptions out;
  out.allow_external_zerostate_pin_diagnostic = external_pin;
  out.network = values.at("--network");
  if (out.network != "mainnet" && out.network != "testnet") {
    throw std::invalid_argument("network must be mainnet or testnet");
  }
  out.zerostate_root = values.at("--zerostate-root");
  out.zerostate_file = values.at("--zerostate-file");
  if (!detail::hex256(out.zerostate_root) || !detail::hex256(out.zerostate_file)) {
    throw std::invalid_argument("both zerostate hashes must be 64 hex digits");
  }
  out.from = detail::decimal(values.at("--from"), "from");
  out.to = detail::decimal(values.at("--to"), "to");
  if (out.from == std::numeric_limits<std::uint32_t>::max() || out.to != out.from + 1) {
    throw std::invalid_argument("exactly two adjacent positive MC seqnos required");
  }
  out.max_tip_roots = detail::decimal(values.at("--max-tip-roots"), "max-tip-roots", 64);
  out.max_transactions = detail::decimal(values.at("--max-transactions"), "max-transactions", 100000);
  out.max_blocks = detail::decimal(values.at("--max-blocks"), "max-blocks", 256);
  if (out.max_blocks < 2) throw std::invalid_argument("max-blocks must cover both MC anchors");
  const auto& scope = values.at("--scope");
  if (scope == "mc-only") out.scope = Scope::masterchain_only;
  else if (scope == "mc-and-basechain") out.scope = Scope::masterchain_and_basechain;
  else throw std::invalid_argument("scope must be mc-only or mc-and-basechain");

  out.db_root = detail::directory(values.at("--db-root"), "db-root");
  out.secondary_work_dir = detail::directory(values.at("--secondary-work-dir"), "secondary-work-dir");
  if (detail::inside(out.db_root, out.secondary_work_dir) ||
      detail::inside(out.secondary_work_dir, out.db_root) ||
      !std::filesystem::is_empty(out.secondary_work_dir)) {
    throw std::invalid_argument("secondary work directory must be empty and disjoint from primary");
  }
  return out;
}

} // namespace ton_analytics::wallets::cli
