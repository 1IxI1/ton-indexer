#pragma once

// Parsing and preflight are independent of TON and never open a NodeDB.
#include <algorithm>
#include <charconv>
#include <cstdint>
#include <filesystem>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>
#include <unistd.h>

namespace tonstat::validators {

struct Options {
  struct McFullId {
    uint32_t seqno{};
    std::string root_hash, file_hash;
  };
  std::filesystem::path db_root, secondary_work_dir;
  std::string network, zerostate_root, zerostate_file, elector_code_hash;
  std::vector<McFullId> anchors;
  uint32_t nofile_budget{}, cpu_seconds{}, wall_seconds{}, memory_mib{};
};

inline uint32_t decimal(const std::string &s) {
  uint32_t n{};
  if (s.empty()) throw std::invalid_argument("empty numeric option");
  auto [end, error] = std::from_chars(s.data(), s.data() + s.size(), n);
  if (error != std::errc{} || end != s.data() + s.size())
    throw std::invalid_argument("invalid unsigned decimal option");
  return n;
}

inline bool nonzero_hex256(const std::string &s) {
  return s.size() == 64 && s.find_first_not_of('0') != std::string::npos &&
         std::all_of(s.begin(), s.end(), [](char c) {
           return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
                  (c >= 'A' && c <= 'F');
         });
}

inline Options::McFullId mc_full_id(const std::string &value) {
  const auto first = value.find(':');
  const auto second = first == std::string::npos ? first : value.find(':', first + 1);
  if (first == std::string::npos || second == std::string::npos ||
      value.find(':', second + 1) != std::string::npos)
    throw std::invalid_argument("MC full ID must be seqno:root-hash:file-hash");
  Options::McFullId out{decimal(value.substr(0, first)),
                        value.substr(first + 1, second - first - 1), value.substr(second + 1)};
  if (out.seqno == 0 || out.seqno == std::numeric_limits<uint32_t>::max() ||
      !nonzero_hex256(out.root_hash) || !nonzero_hex256(out.file_hash))
    throw std::invalid_argument("invalid MC full ID");
  return out;
}

inline bool inside(const std::filesystem::path &child, const std::filesystem::path &parent) {
  auto c = child.begin();
  for (auto p = parent.begin(); p != parent.end(); ++p, ++c)
    if (c == child.end() || *c != *p) return false;
  return true;
}

inline void checked_path(const std::filesystem::path &path) {
  namespace fs = std::filesystem;
  if (!path.is_absolute() || path.empty() || path == path.root_path())
    throw std::invalid_argument("require explicit absolute non-root directory");
  // Reject symlinks in every component, not just in the final component. Also
  // reject dot/dot-dot aliases: canonical isolation must not depend on spelling.
  fs::path prefix;
  for (const auto &component : path) {
    if (component == "." || component == "..")
      throw std::invalid_argument("dot path components are not allowed");
    prefix /= component;
    if (fs::is_symlink(fs::symlink_status(prefix)))
      throw std::invalid_argument("symlinked directory component is not allowed");
  }
  if (!fs::is_directory(path)) throw std::invalid_argument("directory does not exist");
}

inline void preflight_isolation(Options &o) {
  namespace fs = std::filesystem;
  checked_path(o.db_root);
  checked_path(o.secondary_work_dir);
  o.db_root = fs::canonical(o.db_root);
  o.secondary_work_dir = fs::canonical(o.secondary_work_dir);
  if (inside(o.db_root, o.secondary_work_dir) || inside(o.secondary_work_dir, o.db_root))
    throw std::invalid_argument("primary and secondary must be disjoint canonical trees");
  if (!fs::is_empty(o.secondary_work_dir))
    throw std::invalid_argument("secondary directory must be empty");
  if (access(o.db_root.c_str(), R_OK | X_OK) != 0 ||
      access(o.secondary_work_dir.c_str(), R_OK | W_OK | X_OK) != 0)
    throw std::invalid_argument("invalid primary read or secondary write permissions");
}

inline void preflight_paths(Options &o) {
  // Only the already smoke-tested primary location; no archive/remote/custom
  // paths. The secondary's own RocksDB metadata lives outside that tree.
  if (o.db_root != std::filesystem::path("/var/ton-work/db"))
    throw std::invalid_argument("db-root must be /var/ton-work/db");
  preflight_isolation(o);
  checked_path("/var/tmp");
  const auto secondary_parent = std::filesystem::canonical("/var/tmp");
  if (o.secondary_work_dir == secondary_parent ||
      !inside(o.secondary_work_dir, secondary_parent))
    throw std::invalid_argument("secondary workdir must be a separate directory under /var/tmp");
}

// Pure option parsing for offline tests. parse_options below additionally
// performs filesystem checks; both must succeed before an actor is created.
inline Options parse_options_syntax(const std::vector<std::string> &args) {
  // Opt-in + five required single-value flags + up to eight pinned MC IDs
  // + four budgets + at most one optional elector hash: 37 tokens total.
  if (args.size() > 37) throw std::invalid_argument("too many arguments");
  Options o;
  bool opt_in = false, nofile = false, cpu = false, wall = false, memory = false;
  for (size_t i = 0; i < args.size(); ++i) {
    const auto &key = args[i];
    if (key == "--secondary-opt-in") {
      if (opt_in) throw std::invalid_argument("duplicate opt-in");
      opt_in = true;
      continue;
    }
    if (i + 1 == args.size() || args[i + 1].empty() || args[i + 1].rfind("--", 0) == 0)
      throw std::invalid_argument("missing value or unknown flag: " + key);
    const auto &v = args[++i];
    if (key == "--db-root" && o.db_root.empty()) o.db_root = v;
    else if (key == "--secondary-work-dir" && o.secondary_work_dir.empty()) o.secondary_work_dir = v;
    else if (key == "--network" && o.network.empty()) o.network = v;
    else if (key == "--zerostate-root" && o.zerostate_root.empty()) o.zerostate_root = v;
    else if (key == "--zerostate-file" && o.zerostate_file.empty()) o.zerostate_file = v;
    else if (key == "--elector-code-hash" && o.elector_code_hash.empty()) {
      if (!nonzero_hex256(v)) throw std::invalid_argument("invalid elector code hash");
      o.elector_code_hash = v;
    }
    else if (key == "--mc-full-id") {
       if (o.anchors.size() >= 8) throw std::invalid_argument("maximum eight MC anchors per pilot");
      o.anchors.push_back(mc_full_id(v));
    } else if (key == "--nofile-budget" && !nofile) { o.nofile_budget = decimal(v); nofile = true; }
    else if (key == "--cpu-seconds" && !cpu) { o.cpu_seconds = decimal(v); cpu = true; }
    else if (key == "--wall-seconds" && !wall) { o.wall_seconds = decimal(v); wall = true; }
    else if (key == "--memory-mib" && !memory) { o.memory_mib = decimal(v); memory = true; }
    else throw std::invalid_argument("unknown or duplicate option: " + key);
  }
  if (!opt_in || (o.network != "mainnet" && o.network != "testnet") ||
      !nonzero_hex256(o.zerostate_root) || !nonzero_hex256(o.zerostate_file) ||
       o.anchors.empty() || o.anchors.size() > 8 ||
      // The archive reader can require 1,048,576 FDs. The operator must
      // request this explicitly; main also checks the OS hard limit before
      // applying RLIMIT_NOFILE, and the safety gate remains OFF by default.
      !nofile || o.nofile_budget < 512 || o.nofile_budget > 1048576 ||
      !cpu || o.cpu_seconds < 1 || o.cpu_seconds > 900 ||
      !wall || o.wall_seconds < 1 || o.wall_seconds > 300 ||
      !memory || o.memory_mib < 1024 || o.memory_mib > 16384)
    throw std::invalid_argument("explicit secondary opt-in, network, zerostate, 1..8 full MC IDs and capped NOFILE/CPU/wall/memory budgets required");
  for (size_t i = 1; i < o.anchors.size(); ++i)
    if (o.anchors[i].seqno <= o.anchors[i - 1].seqno)
      throw std::invalid_argument("MC full IDs must be unique and increasing");
  return o;
}

inline Options parse_options(const std::vector<std::string> &args) {
  Options o = parse_options_syntax(args);
  preflight_paths(o);
  return o;
}

}  // namespace tonstat::validators
