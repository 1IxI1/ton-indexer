#pragma once

#include <algorithm>
#include <charconv>
#include <cstdint>
#include <filesystem>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>

namespace assets_analytics {

struct CliOptions {
  std::string network, zerostate_root, zerostate_file;
  std::filesystem::path db_root, secondary_work_dir;
  uint32_t from = 0, to = 0;
  uint32_t cpu_seconds = 0, memory_mib = 0, wall_seconds = 0, nofile_budget = 0;
  size_t max_wallets = 0, max_tip_roots = 0;
  std::vector<std::string> wallets;
};

inline bool hex256(const std::string& s) {
  return s.size() == 64 && std::all_of(s.begin(), s.end(), [](char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
           (c >= 'A' && c <= 'F');
  });
}

inline uint32_t decimal(const std::string& s, const char* name) {
  uint32_t out = 0;
  if (s.empty()) throw std::invalid_argument(std::string("empty ") + name);
  const auto [p, ec] = std::from_chars(s.data(), s.data() + s.size(), out);
  if (ec != std::errc{} || p != s.data() + s.size())
    throw std::invalid_argument(std::string("invalid ") + name);
  return out;
}

inline bool nested_in(const std::filesystem::path& child, const std::filesystem::path& parent) {
  auto c = child.begin(), p = parent.begin();
  for (; p != parent.end(); ++p, ++c) if (c == child.end() || *c != *p) return false;
  return true;
}

// Also call immediately before creating DbScanner: the canonical paths passed
// to TON must still name the validated directories. This narrows, but cannot
// eliminate, a filesystem race against a hostile concurrent path mutator.
inline void revalidate_paths(const CliOptions& o) {
  if (o.db_root.empty() || o.secondary_work_dir.empty() ||
      !std::filesystem::is_directory(o.db_root) ||
      !std::filesystem::is_directory(o.secondary_work_dir) ||
      std::filesystem::is_symlink(o.secondary_work_dir) ||
      std::filesystem::canonical(o.db_root) != o.db_root ||
      std::filesystem::canonical(o.secondary_work_dir) != o.secondary_work_dir ||
      nested_in(o.secondary_work_dir, o.db_root) || nested_in(o.db_root, o.secondary_work_dir) ||
      !std::filesystem::is_empty(o.secondary_work_dir))
    throw std::invalid_argument("canonical secondary work directory must remain empty and outside primary tree");
}

// No NodeDB API (or TON headers) is used here. Any invalid option fails before opening a DB.
inline CliOptions parse_cli(const std::vector<std::string>& args) {
  if (args.size() > 32) throw std::invalid_argument("too many CLI arguments");
  CliOptions o;
  bool opted_in = false, from = false, to = false, wallets_cap = false, tips_cap = false;
  bool cpu_cap = false, memory_cap = false, wall_cap = false, nofile_cap = false;
  for (size_t i = 0; i < args.size(); ++i) {
    auto key = args[i];
    if (key == "--readonly-opt-in") {
      if (opted_in) throw std::invalid_argument("duplicate opt-in");
      opted_in = true;
      continue;
    }
    if (i + 1 == args.size()) throw std::invalid_argument("missing option value: " + key);
    auto value = args[++i];
    if (value.empty() || value.rfind("--", 0) == 0) throw std::invalid_argument("empty option value: " + key);
    if (key == "--db-root" && o.db_root.empty()) o.db_root = value;
    else if (key == "--secondary-work-dir" && o.secondary_work_dir.empty()) o.secondary_work_dir = value;
    else if (key == "--network" && o.network.empty()) o.network = value;
    else if (key == "--zerostate-root" && o.zerostate_root.empty()) o.zerostate_root = value;
    else if (key == "--zerostate-file" && o.zerostate_file.empty()) o.zerostate_file = value;
    else if (key == "--from" && !from) { o.from = decimal(value, "from"); from = true; }
    else if (key == "--to" && !to) { o.to = decimal(value, "to"); to = true; }
    else if (key == "--cpu-seconds" && !cpu_cap) {
      o.cpu_seconds = decimal(value, "cpu-seconds"); cpu_cap = true;
    } else if (key == "--memory-mib" && !memory_cap) {
      o.memory_mib = decimal(value, "memory-mib"); memory_cap = true;
    } else if (key == "--wall-seconds" && !wall_cap) {
      o.wall_seconds = decimal(value, "wall-seconds"); wall_cap = true;
    } else if (key == "--nofile-budget" && !nofile_cap) {
      o.nofile_budget = decimal(value, "nofile-budget"); nofile_cap = true;
    }
    else if (key == "--max-wallets" && !wallets_cap) {
      o.max_wallets = decimal(value, "max-wallets"); wallets_cap = true;
    } else if (key == "--max-tip-roots" && !tips_cap) {
      o.max_tip_roots = decimal(value, "max-tip-roots"); tips_cap = true;
    } else if (key == "--wallet") {
      if (o.wallets.size() == 2) throw std::invalid_argument("at most two wallet addresses");
      if (!((value.size() == 66 && value.substr(0, 2) == "0:") ||
            (value.size() == 67 && value.substr(0, 3) == "-1:")))
        throw std::invalid_argument("wallet must be raw 0: or -1: plus 64 hex digits");
      auto pos = value.find(':');
      if (!hex256(value.substr(pos + 1))) throw std::invalid_argument("invalid wallet hash");
      std::transform(value.begin() + static_cast<std::string::difference_type>(pos + 1), value.end(),
                     value.begin() + static_cast<std::string::difference_type>(pos + 1), [](char c) {
                       return c >= 'A' && c <= 'F' ? static_cast<char>(c - 'A' + 'a') : c;
                     });
      if (std::find(o.wallets.begin(), o.wallets.end(), value) != o.wallets.end())
        throw std::invalid_argument("duplicate wallet");
      o.wallets.push_back(value);
    } else throw std::invalid_argument("unknown or duplicate option: " + key);
  }
  if (!opted_in || (o.network != "mainnet" && o.network != "testnet") ||
      !hex256(o.zerostate_root) || !hex256(o.zerostate_file) ||
       !from || !to || o.from == 0 || o.from == std::numeric_limits<uint32_t>::max() || o.to != o.from + 1 ||
       !cpu_cap || o.cpu_seconds < 1 || o.cpu_seconds > 900 ||
       !memory_cap || o.memory_mib < 128 || o.memory_mib > 16384 ||
       !wall_cap || o.wall_seconds < 1 || o.wall_seconds > 300 ||
       !nofile_cap || o.nofile_budget < 1024 || o.nofile_budget > 1048576 ||
       !wallets_cap || o.max_wallets < 1 || o.max_wallets > 2 || o.wallets.empty() ||
       o.wallets.size() > o.max_wallets || !tips_cap || o.max_tip_roots < 1 || o.max_tip_roots > 64)
    throw std::invalid_argument("require opt-in, network/zerostate, two adjacent MC, 1-2 wallets, tips and explicit bounded CPU/memory/wall/NOFILE caps");
  if (o.db_root.empty() || o.secondary_work_dir.empty() ||
      !o.db_root.is_absolute() || !o.secondary_work_dir.is_absolute() ||
      !std::filesystem::is_directory(o.db_root) || !std::filesystem::is_directory(o.secondary_work_dir) ||
      std::filesystem::is_symlink(o.secondary_work_dir))
    throw std::invalid_argument("require existing absolute primary and separate secondary directories");
  o.db_root = std::filesystem::canonical(o.db_root);
  o.secondary_work_dir = std::filesystem::canonical(o.secondary_work_dir);
  revalidate_paths(o);
  return o;
}
}  // namespace assets_analytics
