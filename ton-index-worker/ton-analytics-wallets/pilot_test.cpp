#include "WalletPilot.h"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <string>

using namespace ton_analytics::wallets;
namespace fs = std::filesystem;

int main() {
  if (pilot::kAddressSpaceLimitBytes != (16ull << 30) || pilot::kCpuLimitSeconds != 900 ||
      pilot::kWallLimitSeconds != 300 || pilot::kExternalNofileBudget != 1'048'576) return 8;
  if (!pilot::fits_diagnostic(0, 999'999) || pilot::fits_diagnostic(0, 1'000'000) ||
       pilot::fits_diagnostic(500'000, 500'000) ||
       pilot::fits_diagnostic(1'000'001, 0)) return 7;
  if (pilot::failure_stage_prefix("secondary_catch_up") != "secondary_catch_up: " ||
      pilot::failure_stage_prefix("zerostate_handle_seqno_0") != "zerostate_handle_seqno_0: " ||
      pilot::failure_stage_prefix("cell_reader") != "cell_reader: " ||
      pilot::mc_failure_stage("fetch", 92765119) != "fetch_mc_seqno_92765119" ||
      pilot::mc_failure_stage("parse", 92765120) != "parse_mc_seqno_92765120" ||
      pilot::failure_stage_prefix("zerostate_handle_seqno_0") +
          "ltdb: block not found" != "zerostate_handle_seqno_0: ltdb: block not found" ||
      pilot::failure_stage_prefix(pilot::mc_failure_stage("fetch", 92765119)) +
          "ltdb: block not found" != "fetch_mc_seqno_92765119: ltdb: block not found") return 11;
  using pilot::same_unique_full_ids;
  if (!same_unique_full_ids(std::vector<std::string>{"0:shard:1:rootA:fileA", "0:shard:2:rootB:fileB"},
                            std::vector<std::string>{"0:shard:2:rootB:fileB", "0:shard:1:rootA:fileA"})) return 5;
  if (same_unique_full_ids(std::vector<std::string>{"0:shard:1:rootA:fileA"},
                           std::vector<std::string>{"0:shard:1:rootA:fileOTHER"}) ||
      same_unique_full_ids(std::vector<std::string>{"0:shard:1:rootA:fileA"},
                           std::vector<std::string>{"0:shard:1:rootOTHER:fileA"}) ||
      same_unique_full_ids(std::vector<std::string>{"a", "a"}, std::vector<std::string>{"a", "a"}) ||
      same_unique_full_ids(std::vector<std::string>{}, std::vector<std::string>{})) return 6;

  bool failed = false;
  try { pilot::require_review(false, true); } catch (const std::runtime_error&) { failed = true; }
  if (!failed) return 1;
  failed = false;
  try { pilot::require_review(true, false); } catch (const std::runtime_error&) { failed = true; }
  if (!failed) return 2;
  pilot::require_review(true, true);

  const auto base = fs::temp_directory_path() / ("wallet-pilot-test-" +
      std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
  const auto db = base / "primary";
  const auto secondary = base / "secondary";
  fs::create_directories(db);
  fs::create_directories(secondary);
  cli::WalletCliOptions o;
  o.db_root = fs::canonical(db);
  o.secondary_work_dir = fs::canonical(secondary);
  pilot::revalidate_paths(o);
  const std::vector<std::string> valid_args = {
      "--secondary-opt-in", "--network", "mainnet",
      "--zerostate-root", std::string(64, 'a'), "--zerostate-file", std::string(64, 'b'),
      "--db-root", o.db_root.string(), "--secondary-work-dir", o.secondary_work_dir.string(),
      "--from", "92765119", "--to", "92765120", "--max-tip-roots", "4",
      "--max-transactions", "500", "--max-blocks", "8", "--scope", "mc-and-basechain"};
  const auto accepted = cli::parse_cli(valid_args);
  if (accepted.from != 92765119 || accepted.to != 92765120 || accepted.max_tip_roots != 4 ||
       accepted.max_blocks != 8 || accepted.max_transactions != 500) return 9;
  cli::WalletCliOptions pinned;
  pinned.network = "mainnet";
  pinned.zerostate_root = "17a3a92992aabea785a7a090985a265cd31f323d849da51239737e321fb05569";
  pinned.zerostate_file = "5e994fcf4d425c0a6ce6a792594b7173205f740a39cd56f537defd28b48a0f6e";
  if (!pilot::published_network_pin(pinned) ||
      pilot::external_pin_allowed(pinned, 651, "ltdb: block not found")) return 12;
  pinned.allow_external_zerostate_pin_diagnostic = true;
  if (!pilot::external_pin_allowed(pinned, 651, "ltdb: block not found") ||
      pilot::external_pin_allowed(pinned, 652, "ltdb: block not found") ||
      pilot::external_pin_allowed(pinned, 651, "ltdb: block not found: extra") ||
      pilot::external_pin_allowed(pinned, 651, "not found")) return 13;
  pinned.network = "testnet"; // Cannot cross-apply mainnet's independently published pin.
  if (pilot::published_network_pin(pinned) ||
      pilot::external_pin_allowed(pinned, 651, "ltdb: block not found")) return 14;
  pinned.zerostate_root = "823f81f306ff02694f935cf5021548e3ce2b86b529812af6a12148879e95a128";
  pinned.zerostate_file = "67e20ac184b9e039a62667acc3f9c00f90f359a76738233379efa47604980ce8";
  if (!pilot::external_pin_allowed(pinned, 651, "ltdb: block not found")) return 15;
  pinned.zerostate_file[0] = '0';
  if (pilot::external_pin_allowed(pinned, 651, "ltdb: block not found")) return 16;
  if (pilot::can_build_stage(false, cli::Scope::masterchain_and_basechain, true) ||
      pilot::can_build_stage(true, cli::Scope::masterchain_only, true) ||
      pilot::can_build_stage(true, cli::Scope::masterchain_and_basechain, false) ||
      !pilot::can_build_stage(true, cli::Scope::masterchain_and_basechain, true)) return 17;
  const auto fields = pilot::diagnostic_incompleteness_fields();
  if (fields.find("\"daily_activations\":null") == std::string::npos ||
      fields.find("\"cumulative_activations\":null") == std::string::npos ||
      fields.find("\"dau\":null") == std::string::npos ||
      fields.find("\"mau_30d\":null") == std::string::npos ||
      fields.find("\"writer_committed\":false") == std::string::npos ||
      fields.find("\"publication_ready\":false") == std::string::npos ||
      fields.find("\"lifetime_complete\":false") == std::string::npos) return 18;
  for (const auto* flag : {"--memory-mib", "--cpu-seconds", "--wall-seconds", "--nofile-budget"}) {
    auto override_args = valid_args;
    override_args.push_back(flag);
    override_args.push_back("999999");
    bool rejected = false;
    try { (void)cli::parse_cli(override_args); }
    catch (const std::invalid_argument&) { rejected = true; }
    if (!rejected) return 10;
  }
  std::ofstream(secondary / "occupied") << "no reuse";
  failed = false;
  try { pilot::revalidate_paths(o); } catch (const std::invalid_argument&) { failed = true; }
  if (!failed) return 3;
  fs::remove(secondary / "occupied");
  o.secondary_work_dir = db;
  failed = false;
  try { pilot::revalidate_paths(o); } catch (const std::invalid_argument&) { failed = true; }
  if (!failed) return 4;
  fs::remove(secondary);
  fs::remove(db);
  fs::remove(base);
}
