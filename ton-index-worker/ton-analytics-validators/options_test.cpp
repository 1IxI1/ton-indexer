#include "Options.h"

#include <cassert>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <unistd.h>
#include <vector>

namespace fs = std::filesystem;
using tonstat::validators::Options;
using tonstat::validators::parse_options;
using tonstat::validators::parse_options_syntax;

int main() {
  // Synthetic directories only: no TON header, NodeDB open, or live archive.
  const auto base = fs::canonical(fs::temp_directory_path()) /
                    ("validators-options-" + std::to_string(getpid()));
  const auto primary = base / "primary", secondary = base / "secondary";
  fs::create_directories(primary);
  fs::create_directories(secondary);
  try {
    const std::string root(64, 'a'), file(64, 'b');
    const std::string mc1 = "89799586:" + root + ":" + file;
    const std::string mc2 = "89799587:" + file + ":" + root;
    std::vector<std::string> args{
        "--secondary-opt-in", "--db-root", primary.string(),
        "--secondary-work-dir", secondary.string(), "--network", "mainnet",
        "--zerostate-root", root, "--zerostate-file", file,
        "--mc-full-id", mc1, "--mc-full-id", mc2,
        "--nofile-budget", "1048576", "--cpu-seconds", "900",
        "--wall-seconds", "300", "--memory-mib", "16384"};
    const auto syntax = parse_options_syntax(args);
    assert(syntax.elector_code_hash.empty()); // absent: decoder stays disabled
    assert(syntax.anchors.size() == 2 && syntax.anchors[0].seqno == 89799586);
    assert(syntax.anchors[0].root_hash == root && syntax.anchors[0].file_hash == file);
    assert(syntax.nofile_budget == 1048576 && syntax.cpu_seconds == 900 &&
           syntax.wall_seconds == 300 && syntax.memory_mib == 16384);
    auto one = args;
    one.erase(one.begin() + 13, one.begin() + 15);
    assert(parse_options_syntax(one).anchors.size() == 1);

    auto rejects_syntax = [](const std::vector<std::string> &a) {
      try { (void)parse_options_syntax(a); }
      catch (const std::exception &) { return; }
      throw std::runtime_error("unsafe syntax accepted");
    };
    const std::string elector = "A1" + std::string(62, 'b');
    auto with_elector = args;
    with_elector.push_back("--elector-code-hash");
    with_elector.push_back(elector);
    assert(parse_options_syntax(with_elector).elector_code_hash == elector);
    for (const auto &invalid : {std::string(63, 'a'), std::string(65, 'a'),
                                std::string(64, '0'), "G" + std::string(63, 'a')}) {
      auto candidate = with_elector;
      candidate.back() = invalid;
      rejects_syntax(candidate);
    }
    auto missing_elector = args;
    missing_elector.push_back("--elector-code-hash");
    rejects_syntax(missing_elector);
    auto duplicate_elector = one;
    duplicate_elector.push_back("--elector-code-hash");
    duplicate_elector.push_back(elector);
    duplicate_elector.push_back("--elector-code-hash");
    duplicate_elector.push_back(elector);
    rejects_syntax(duplicate_elector);
    auto over_cap = with_elector;
    over_cap.push_back("--elector-code-hash");
    over_cap.push_back(elector);
    rejects_syntax(over_cap);
    auto change = [&](size_t i, const std::string &value) {
      auto candidate = args;
      candidate[i] = value;
      rejects_syntax(candidate);
    };
    auto omitted = [&](size_t first) {
      auto candidate = args;
      candidate.erase(candidate.begin() + static_cast<std::ptrdiff_t>(first),
                      candidate.begin() + static_cast<std::ptrdiff_t>(first + 2));
      rejects_syntax(candidate);
    };
    auto no_opt_in = args;
    no_opt_in.erase(no_opt_in.begin());
    rejects_syntax(no_opt_in);
    auto no_anchors = args;
    no_anchors.erase(no_anchors.begin() + 11, no_anchors.begin() + 15);
    rejects_syntax(no_anchors);
    omitted(15); omitted(17); omitted(19); omitted(21);
    change(8, std::string(64, '0'));
    change(12, "89799586:" + root + ":" + std::string(64, '0'));
    change(12, "89799586:" + root);
    change(12, "89799586:" + root + ":" + file + ":extra");
    change(12, "0:" + root + ":" + file);
    change(12, "-1:" + root + ":" + file);
    change(14, mc1); // duplicate seqno, including even if hashes differ
    change(14, "89799585:" + root + ":" + file); // not increasing
    change(16, "1048577"); change(18, "901");
    change(20, "301"); change(22, "16385");
    auto three = args;
    three.push_back("--mc-full-id"); three.push_back("89799588:" + root + ":" + file);
    assert(parse_options_syntax(three).anchors.size() == 3);
    auto eight = one;
    for (int i = 1; i < 8; ++i) {
      eight.push_back("--mc-full-id");
      eight.push_back(std::to_string(89799586 + i) + ":" + root + ":" + file);
    }
    assert(parse_options_syntax(eight).anchors.size() == 8);
    auto nine = eight;
    nine.push_back("--mc-full-id"); nine.push_back("89799594:" + root + ":" + file);
    rejects_syntax(nine);
    change(11, "--mc-seqno"); // old seqno-only CLI is forbidden
    change(19, "--io-seconds"); // --wall-seconds is the total deadline

    Options isolated = syntax;
    tonstat::validators::preflight_isolation(isolated);
    assert(isolated.db_root == fs::canonical(primary));
    auto rejects_paths = [](Options candidate) {
      try { tonstat::validators::preflight_isolation(candidate); }
      catch (const std::exception &) { return; }
      throw std::runtime_error("unsafe paths accepted");
    };
    auto relative = syntax; relative.db_root = "relative/db"; rejects_paths(relative);
    auto same = syntax; same.secondary_work_dir = primary; rejects_paths(same);
    fs::create_directory_symlink(primary, base / "alias");
    auto link = syntax; link.db_root = base / "alias"; rejects_paths(link);
    fs::rename(secondary, base / "secondary-original");
    fs::create_directory_symlink(primary, secondary);
    rejects_paths(syntax); // path substituted between parse and pre-open check
    fs::remove(secondary);
    fs::rename(base / "secondary-original", secondary);
    fs::create_directories(primary / "inside");
    auto nested = syntax; nested.secondary_work_dir = primary / "inside"; rejects_paths(nested);
    std::ofstream(secondary / "existing") << "occupied";
    rejects_paths(syntax);
    fs::remove(secondary / "existing");
    try { (void)parse_options(args); throw std::runtime_error("arbitrary db-root accepted"); }
    catch (const std::invalid_argument &) {}
  } catch (...) {
    fs::remove_all(base);
    throw;
  }
  fs::remove_all(base);
  std::cout << "validators options: PASS\n";
}
