#pragma once

#include "common/checksum.h"
#include "crypto/common/refint.h"
#include <cstdint>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace gram {

// BlockIdExt.file_hash hashes the *stored block BoC bytes*, not its cell
// representation hash or BlockData::file_hash() (metadata). Match TON's
// import-db-slice-local.cpp and BlockData::data() interface exactly.
inline bool block_file_hash_matches(td::Slice boc, const td::Bits256& expected) {
  return !boc.empty() && td::sha256_bits256(boc) == expected;
}

inline std::string shard_hex(uint64_t shard) {
  constexpr char digits[] = "0123456789abcdef";
  std::string result(16, '0');
  for (int i = 15; i >= 0; --i, shard >>= 4) result[i] = digits[shard & 15];
  return result;
}

inline std::string lowercase_hex(std::string hex) {
  for (char& c : hex) {
    if (c >= 'A' && c <= 'F') c = static_cast<char>(c - 'A' + 'a');
  }
  return hex;
}

inline bool path_within(const std::filesystem::path& path, const std::filesystem::path& parent) {
  auto p = path.begin();
  for (auto base = parent.begin(); base != parent.end(); ++base, ++p) {
    if (p == path.end() || *p != *base) return false;
  }
  return true;
}

// Both directories must already exist. Do not allow secondary metadata to be
// written through a symlink or under/above the primary, even when its spelling
// uses '..'. The TON RootDb must repeat this check at its own open boundary.
inline std::pair<std::filesystem::path, std::filesystem::path> validate_secondary_paths(
    const std::filesystem::path& primary, const std::filesystem::path& secondary) {
  namespace fs = std::filesystem;
  if (primary.empty() || secondary.empty() || !fs::is_directory(primary) || !fs::is_directory(secondary)) {
    throw std::invalid_argument("primary and secondary must be existing directories");
  }
  // Inspect the original component chain BEFORE lexical normalization: a
  // "symlink/.." spelling must not hide that a symlink was traversed.
  auto secondary_absolute = fs::absolute(secondary);
  fs::path component;
  for (const auto& part : secondary_absolute) {
    component /= part;
    std::error_code error;
    if (fs::is_symlink(fs::symlink_status(component, error)) || error) {
      throw std::invalid_argument("secondary path has a symlink or inaccessible component");
    }
  }
  auto primary_real = fs::canonical(primary);
  auto secondary_real = fs::canonical(secondary_absolute);
  if (path_within(secondary_real, primary_real) || path_within(primary_real, secondary_real)) {
    throw std::invalid_argument("secondary working directory overlaps primary DB root");
  }
  return {std::move(primary_real), std::move(secondary_real)};
}

template <class ID>
bool single_predecessor_matches(const std::vector<ID>& raw_prev, const ID& previous, bool after_split) {
  return !after_split && raw_prev.size() == 1 && raw_prev.front() == previous;
}

inline td::RefInt256 residual(const td::RefInt256& previous, const td::RefInt256& current,
                              const td::RefInt256& created, const td::RefInt256& burned) {
  return current - previous - created + burned;
}

inline std::string json_string(const std::string& input) {
  std::string out = "\"";
  constexpr char hex[] = "0123456789abcdef";
  for (unsigned char c : input) {
    switch (c) {
      case '"': out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      default:
        if (c < 0x20) {
          out += "\\u00";
          out += hex[c >> 4];
          out += hex[c & 15];
        } else {
          out += static_cast<char>(c);
        }
    }
  }
  return out + '"';
}

inline std::string amount(const td::RefInt256& value) {
  return json_string(value->to_dec_string());
}

}  // namespace gram
