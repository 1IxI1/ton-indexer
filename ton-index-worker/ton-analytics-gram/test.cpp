#include "record.h"
#include <chrono>
#include <filesystem>
#include <iostream>

namespace {
bool rejects(const std::filesystem::path& primary, const std::filesystem::path& secondary) {
  try {
    gram::validate_secondary_paths(primary, secondary);
    return false;
  } catch (const std::exception&) {
    return true;
  }
}

bool check_secondary_guard() {
  namespace fs = std::filesystem;
  auto base = fs::canonical(fs::temp_directory_path()) /
              ("ton-gram-guard-test-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
  if (!fs::create_directory(base)) return false;
  bool ok = false;
  try {
    auto primary = base / "primary";
    auto secondary = base / "secondary";
    fs::create_directories(primary / "nested");
    fs::create_directory(secondary);
    fs::create_directory(base / "secondary_parent");
    fs::create_directory(base / "secondary_parent" / "child");
    fs::create_directory(base / "outer");
    fs::create_directory(base / "outer" / "db");
    fs::create_directory_symlink(primary, base / "primary_alias");
    fs::create_directory_symlink(secondary, base / "secondary_alias");
    fs::create_directory_symlink(base / "secondary_parent", base / "parent_alias");
    auto [canon_primary, canon_secondary] = gram::validate_secondary_paths(primary, secondary);
    ok = canon_primary == fs::canonical(primary) && canon_secondary == fs::canonical(secondary) &&
         rejects(primary, primary) && rejects(primary, primary / "nested") &&
         rejects(base / "outer" / "db", base / "outer") &&
         rejects(primary, base / "primary_alias") && rejects(primary, base / "secondary_alias") &&
         rejects(primary, base / "parent_alias" / "child") &&
         rejects(primary, base / "primary_alias" / ".." / "secondary") &&
         rejects(primary, base / "missing-secondary");
  } catch (const std::exception&) {
    ok = false;
  }
  fs::remove_all(base);  // Exactly the unique directory made by this test.
  return ok;
}
}  // namespace

int main() {
  td::Bits256 expected_file_hash;
  if (expected_file_hash.from_hex(td::Slice("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")) != 256) {
    std::cerr << "bad SHA256 fixture\n";
    return 1;
  }
  auto prev = td::dec_string_to_int256(std::string("5249025236092902378"));
  auto next = td::dec_string_to_int256(std::string("5249025238792216541"));
  auto created = td::make_refint(2700000000LL);
  auto burned = td::make_refint(685837);
  if (gram::residual(prev, next, created, burned)->to_dec_string() != "0" ||
      gram::residual(prev, next + 1, created, burned)->to_dec_string() != "1" ||
      gram::residual(prev, next - 1, created, burned)->to_dec_string() != "-1" ||
      gram::json_string("a\"\\\n\x01") != "\"a\\\"\\\\\\n\\u0001\"" ||
      gram::amount(prev) != "\"5249025236092902378\"" ||
      !gram::block_file_hash_matches(td::Slice("abc"), expected_file_hash) ||
      gram::block_file_hash_matches(td::Slice("abd"), expected_file_hash) ||
      gram::block_file_hash_matches(td::Slice(""), expected_file_hash) ||
      gram::shard_hex(0) != "0000000000000000" ||
      gram::shard_hex(0x8000000000000000ULL) != "8000000000000000" ||
      gram::shard_hex(0xffffffffffffffffULL) != "ffffffffffffffff" ||
      gram::lowercase_hex("ABCDEF0123") != "abcdef0123" ||
      !gram::single_predecessor_matches(std::vector<int>{7}, 7, false) ||
      gram::single_predecessor_matches(std::vector<int>{8}, 7, false) ||
      gram::single_predecessor_matches(std::vector<int>{}, 7, false) ||
      gram::single_predecessor_matches(std::vector<int>{7, 7}, 7, false) ||
      gram::single_predecessor_matches(std::vector<int>{7}, 7, true) ||
      !check_secondary_guard()) {
    std::cerr << "invariant/BoC hash/BlockID/predecessor/secondary guard test failed\n";
    return 1;
  }
}
