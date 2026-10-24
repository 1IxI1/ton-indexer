#include "CliOptions.h"

#ifdef NDEBUG
#undef NDEBUG
#endif
#include <cassert>
#include <chrono>
#include <filesystem>
#include <string>
#include <vector>

namespace fs = std::filesystem;
using assets_analytics::parse_cli;

static bool rejected(std::vector<std::string> args) {
  try { (void)parse_cli(args); return false; }
  catch (const std::exception&) { return true; }
}

int main() {
  const fs::path tmp = fs::temp_directory_path() /
      ("assets-cli-test-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
  // Test only creates/removes its uniquely named children, never a NodeDB.
  const auto base = tmp / "primary";
  const auto secondary = tmp / "secondary";
  fs::create_directories(base / "nested");
  fs::create_directories(secondary);
  std::string h(64, 'a');
  std::vector<std::string> args{
    "--readonly-opt-in", "--db-root", base.string(), "--secondary-work-dir", secondary.string(),
    "--network", "mainnet", "--zerostate-root", h, "--zerostate-file", h,
    "--from", "40014273", "--to", "40014274", "--max-wallets", "2",
    "--max-tip-roots", "16", "--wallet", "0:" + h,
    "--cpu-seconds", "900", "--memory-mib", "16384", "--wall-seconds", "300",
    "--nofile-budget", "1048576"};
  auto valid = parse_cli(args);
  assert(valid.from == 40014273 && valid.to == 40014274 && valid.wallets.size() == 1);
  assert(valid.cpu_seconds == 900 && valid.memory_mib == 16384 &&
         valid.wall_seconds == 300 && valid.nofile_budget == 1048576);
  assets_analytics::revalidate_paths(valid);
  auto remove_key = [&](const std::string& key, bool flag = false) {
    auto copy = args;
    auto p = std::find(copy.begin(), copy.end(), key);
    assert(p != copy.end());
    copy.erase(p, p + (flag ? 1 : 2));
    return copy;
  };
  for (auto key : {"--readonly-opt-in", "--db-root", "--secondary-work-dir", "--network",
                   "--zerostate-root", "--zerostate-file", "--from", "--to", "--wallet",
                   "--max-wallets", "--max-tip-roots", "--cpu-seconds", "--memory-mib",
                   "--wall-seconds", "--nofile-budget"}) {
    assert(rejected(remove_key(key, std::string(key) == "--readonly-opt-in")));
  }
  auto replace = [&](const std::string& key, const std::string& value) {
    auto copy = args;
    *std::next(std::find(copy.begin(), copy.end(), key)) = value;
    return copy;
  };
  for (auto value : {"40014273", "40014275", "0", "4294967295", "-1", "abc", "4294967296"})
    assert(rejected(replace("--to", value)));
  for (auto value : {"0", "3", "-1", "4294967296"}) assert(rejected(replace("--max-wallets", value)));
  for (auto value : {"0", "65", "-1"}) assert(rejected(replace("--max-tip-roots", value)));
  for (auto value : {"0", "901", "-1", "4294967296", "abc"})
    assert(rejected(replace("--cpu-seconds", value)));
  for (auto value : {"0", "127", "16385", "-1", "4294967296", "abc"})
    assert(rejected(replace("--memory-mib", value)));
  for (auto value : {"0", "301", "-1", "4294967296", "abc"})
    assert(rejected(replace("--wall-seconds", value)));
  for (auto value : {"0", "1023", "1048577", "-1", "4294967296", "abc"})
    assert(rejected(replace("--nofile-budget", value)));
  // Smaller, explicitly requested diagnostic limits are legal; they are not
  // implicit defaults and must not be used for the archive pilot after its
  // measured 2.54 GiB / ~94 CPU-second cold open.
  auto diagnostic = args;
  *std::next(std::find(diagnostic.begin(), diagnostic.end(), "--cpu-seconds")) = "60";
  *std::next(std::find(diagnostic.begin(), diagnostic.end(), "--memory-mib")) = "2048";
  *std::next(std::find(diagnostic.begin(), diagnostic.end(), "--wall-seconds")) = "90";
  *std::next(std::find(diagnostic.begin(), diagnostic.end(), "--nofile-budget")) = "65536";
  auto allowed_diagnostic = parse_cli(diagnostic);
  assert(allowed_diagnostic.cpu_seconds == 60 && allowed_diagnostic.memory_mib == 2048 &&
         allowed_diagnostic.wall_seconds == 90 && allowed_diagnostic.nofile_budget == 65536);
  for (auto key : {"--cpu-seconds", "--memory-mib", "--wall-seconds", "--nofile-budget"}) {
    auto duplicate = args;
    duplicate.insert(duplicate.end(), {key, "1"});
    assert(rejected(duplicate));
  }
  for (const auto& value : std::vector<std::string>{"", "0:abc", "0:" + std::string(64, 'g'), "1:" + h, "EQ" + h})
    assert(rejected(replace("--wallet", value)));
  for (auto key : {"--zerostate-root", "--zerostate-file"})
    assert(rejected(replace(key, std::string(63, 'a'))));
  assert(rejected(replace("--network", "unknown")));
  assert(rejected(replace("--db-root", "relative")));
  assert(rejected(replace("--secondary-work-dir", (base / "nested").string())));
  assert(rejected(replace("--secondary-work-dir", base.string())));
  assert(rejected(replace("--secondary-work-dir", tmp.string())));
  assert(rejected(replace("--secondary-work-dir", (tmp / "missing").string())));
  fs::create_directory_symlink(base / "nested", tmp / "alias");
  assert(rejected(replace("--secondary-work-dir", (tmp / "alias").string())));
  fs::remove(tmp / "alias");
  fs::create_directory_symlink(base, tmp / "primary-alias");
  // The final component is not a symlink, but an ancestor resolves inside
  // canonical primary; lexical prefix checks alone would incorrectly accept it.
  assert(rejected(replace("--secondary-work-dir", (tmp / "primary-alias" / "nested").string())));
  fs::remove(tmp / "primary-alias");
  fs::create_directory_symlink(tmp, tmp / "parent-alias");
  auto via_parent = parse_cli(replace("--secondary-work-dir", (tmp / "parent-alias" / "secondary").string()));
  assert(via_parent.secondary_work_dir == fs::canonical(secondary));
  fs::remove(tmp / "parent-alias");
  fs::create_directory_symlink(secondary, tmp / "sec-alias");
  assert(rejected(replace("--secondary-work-dir", (tmp / "sec-alias").string())));
  fs::remove(tmp / "sec-alias");
  fs::create_directory(secondary / "leftover");
  assert(rejected(args));
  try { assets_analytics::revalidate_paths(valid); assert(false); }
  catch (const std::invalid_argument&) {}
  fs::remove(secondary / "leftover");
  assert(rejected([&] { auto a = args; a.push_back("--readonly-opt-in"); return a; }()));
  assert(rejected([&] { auto a = args; a.insert(a.end(), {"--wallet", "0:" + h}); return a; }()));
  assert(rejected([&] { auto a = args; a.insert(a.end(), {"--wallet", "0:" + std::string(64, 'A')}); return a; }()));
  assert(rejected([&] { auto a = args; a.insert(a.end(), {"--max-tip-roots", "1"}); return a; }()));
  assert(rejected([&] { auto a = args; a.insert(a.end(), {"--primary", "yes"}); return a; }()));
  auto two = args;
  two.insert(two.end(), {"--wallet", "-1:" + std::string(64, 'b')});
  assert(parse_cli(two).wallets.size() == 2);
  two.insert(two.end(), {"--wallet", "0:" + std::string(64, 'c')});
  assert(rejected(two));
  fs::remove(base / "nested");
  fs::remove(base);
  fs::remove(secondary);
  fs::remove(tmp);
}
