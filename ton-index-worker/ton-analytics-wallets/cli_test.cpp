#include "WalletCliOptions.h"

#ifdef NDEBUG
#undef NDEBUG
#endif
#include <cassert>
#include <chrono>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace fs = std::filesystem;
using ton_analytics::wallets::cli::parse_cli;
using ton_analytics::wallets::cli::Scope;

static bool rejected(const std::vector<std::string>& args) {
  try {
    (void)parse_cli(args);
    return false;
  } catch (const std::exception&) {
    return true;
  }
}

int main() {
  // Only create/remove this test's own temporary directories, never a NodeDB.
  const auto temp_root = fs::canonical(fs::temp_directory_path());
  const auto unique = "wallet-cli-test-" +
      std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
  fs::path tmp;
  bool owned = false;
  for (int suffix = 0; suffix < 100; ++suffix) {
    tmp = temp_root / (unique + "-" + std::to_string(suffix));
    if (fs::create_directory(tmp)) { owned = true; break; }
  }
  if (!owned) throw std::runtime_error("could not create unique test directory");
  const auto primary = tmp / "primary";
  const auto secondary = tmp / "secondary";
  fs::create_directories(primary / "nested");
  fs::create_directory(secondary);

  const std::string root(64, 'a'), file(64, 'B');
  const std::vector<std::string> args{
      "--secondary-opt-in", "--network", "testnet", "--zerostate-root", root,
      "--zerostate-file", file, "--db-root", primary.string(),
      "--secondary-work-dir", secondary.string(), "--from", "40014273", "--to", "40014274",
      "--max-tip-roots", "16", "--max-transactions", "1000", "--max-blocks", "32",
      "--scope", "mc-and-basechain"};
  const auto valid = parse_cli(args);
  assert(valid.from == 40014273 && valid.to == 40014274);
  assert(valid.db_root == primary && valid.secondary_work_dir == secondary);
  assert(valid.max_tip_roots == 16 && valid.max_transactions == 1000 && valid.max_blocks == 32);
  assert(valid.scope == Scope::masterchain_and_basechain);
  assert(!valid.allow_external_zerostate_pin_diagnostic);
  auto external_args = args;
  external_args.push_back("--allow-external-zerostate-pin-diagnostic");
  assert(parse_cli(external_args).allow_external_zerostate_pin_diagnostic);
  external_args.push_back("--allow-external-zerostate-pin-diagnostic");
  assert(rejected(external_args));
  external_args.pop_back();
  external_args.push_back("true"); // switch takes no value
  assert(rejected(external_args));

  auto remove = [&](const std::string& key) {
    auto copy = args;
    auto found = std::find(copy.begin(), copy.end(), key);
    assert(found != copy.end());
    copy.erase(found, found + (key == "--secondary-opt-in" ? 1 : 2));
    return copy;
  };
  auto replace = [&](const std::string& key, const std::string& value) {
    auto copy = args;
    auto found = std::find(copy.begin(), copy.end(), key);
    assert(found != copy.end());
    *std::next(found) = value;
    return copy;
  };
  for (const auto& key : {"--secondary-opt-in", "--network", "--zerostate-root",
                          "--zerostate-file", "--db-root", "--secondary-work-dir",
                          "--from", "--to", "--max-tip-roots", "--max-transactions",
                          "--max-blocks", "--scope"}) {
    assert(rejected(remove(key)));
    auto duplicate = args;
    const auto found = std::find(args.begin(), args.end(), key);
    assert(found != args.end());
    duplicate.insert(duplicate.end(), found, found +
        (std::string(key) == "--secondary-opt-in" ? 1 : 2));
    assert(rejected(duplicate));
  }
  auto duplicate_within_limit = remove("--scope");
  duplicate_within_limit.insert(duplicate_within_limit.end(), {"--from", "40014273"});
  assert(rejected(duplicate_within_limit));
  duplicate_within_limit = remove("--scope");
  duplicate_within_limit.push_back("--secondary-opt-in");
  assert(rejected(duplicate_within_limit));
  for (const auto& key : {"--from", "--to"}) {
    for (const auto& bad : {"0", "-1", "+1", "garbage", "1a", "4294967296", "", " 1"}) {
      assert(rejected(replace(key, bad)));
    }
  }
  for (const auto& bad : {"40014273", "40014275", "1", "4294967295"}) {
    assert(rejected(replace("--to", bad)));
  }
  assert(rejected(replace("--from", "4294967295")));
  assert(rejected(replace("--from", "1"))); // Adjacency remains required.
  for (const auto& [key, upper] : std::vector<std::pair<std::string, std::string>>{
           {"--max-tip-roots", "65"}, {"--max-transactions", "100001"},
           {"--max-blocks", "257"}}) {
    for (const auto& bad : {std::string("0"), std::string("-1"), upper,
                            std::string("4294967296"), std::string("1junk")}) {
      assert(rejected(replace(key, bad)));
    }
  }
  assert(rejected(replace("--max-blocks", "1")));
  assert(parse_cli(replace("--scope", "mc-only")).scope == Scope::masterchain_only);
  for (const auto& bad : {"", "all", "mc-and-all", "mc-only,mc-and-basechain"}) {
    assert(rejected(replace("--scope", bad)));
  }
  for (const auto& bad : {"devnet", "MAINNET", ""}) assert(rejected(replace("--network", bad)));
  for (const auto& key : {"--zerostate-root", "--zerostate-file"}) {
    for (const auto& bad : {std::string(63, 'a'), std::string(64, 'g'), std::string()}) {
      assert(rejected(replace(key, bad)));
    }
  }

  assert(rejected(replace("--db-root", "relative")));
  assert(rejected(replace("--secondary-work-dir", "relative")));
  assert(rejected(replace("--db-root", (tmp / "missing").string())));
  assert(rejected(replace("--secondary-work-dir", (tmp / "missing").string())));
  assert(rejected(replace("--secondary-work-dir", (primary / "nested").string())));
  assert(rejected(replace("--secondary-work-dir", primary.string())));
  assert(rejected(replace("--secondary-work-dir", tmp.string())));
  assert(rejected(replace("--db-root", tmp.string()))); // Secondary nested in primary.
  assert(rejected(replace("--secondary-work-dir", (tmp / "." / "secondary").string())));
  assert(rejected(replace("--secondary-work-dir", (primary / ".." / "secondary").string())));
  assert(rejected(replace("--db-root", (tmp / "secondary" / ".." / "primary").string())));
  assert(rejected(replace("--db-root", primary.string() + "/")));
  assert(rejected(replace("--secondary-work-dir", secondary.string() + "//")));

  fs::create_directory_symlink(secondary, tmp / "secondary-alias");
  assert(rejected(replace("--secondary-work-dir", (tmp / "secondary-alias").string())));
  assert(rejected(replace("--secondary-work-dir", (tmp / "secondary-alias" / "..").string())));
  fs::remove(tmp / "secondary-alias");
  fs::create_directory_symlink(primary, tmp / "primary-alias");
  assert(rejected(replace("--db-root", (tmp / "primary-alias").string())));
  assert(rejected(replace("--db-root", (tmp / "primary-alias" / "nested").string())));
  fs::remove(tmp / "primary-alias");
  fs::create_directory(secondary / "leftover");
  assert(rejected(args));
  fs::remove(secondary / "leftover");

  for (const auto& key : {"--readonly-opt-in", "--dbs-readonly", "--primary",
                          "--ch-password", "--ch-write", "--output"}) {
    auto extra = args;
    extra.insert(extra.end(), {key, "anything"});
    assert(rejected(extra));
  }
  assert(rejected({}));
  auto nul = args;
  *std::next(std::find(nul.begin(), nul.end(), "--db-root")) += std::string(1, '\0') + "malicious";
  assert(rejected(nul));

  fs::remove(primary / "nested");
  fs::remove(primary);
  fs::remove(secondary);
  fs::remove(tmp);
}
