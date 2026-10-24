#include "Progress.h"
#include "Frontier.h"
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <unistd.h>

using namespace tonstat::runner;
namespace {
void check(bool ok) { if (!ok) throw std::runtime_error("test failed"); }
template <class F> void fails(F fn) {
  bool caught = false; try { fn(); } catch (const std::exception&) { caught = true; } check(caught);
}
// Digest seam is for filesystem transaction tests only. Production uses SHA256.
std::string identity(const std::string& s) { return std::to_string(std::hash<std::string>{}(s)); }
struct Temp {
  std::filesystem::path path;
  Temp() {
    path = std::filesystem::canonical(std::filesystem::temp_directory_path()) / ("analytics-runner-tests-" + std::to_string(getpid()));
    check(std::filesystem::create_directory(path));
  }
  ~Temp() { std::filesystem::remove_all(path); }
  auto dir(const std::string& name) { auto p = path / name; std::filesystem::create_directory(p); return p; }
};
void options(Temp& t) {
  std::vector<std::string> args{"--network", "mainnet", "--zerostate-root", std::string(64, '1'),
      "--zerostate-file", std::string(64, '2'), "--from", "100", "--to", "103"};
  auto o = parse_options(args); check(o.anchors.size() == 4 && !o.supply && !o.accounts_limit);
  auto large = args; large.back() = "104"; fails([&] { parse_options(large); });
  large.insert(large.end(), {"--max-anchors", "5"}); check(parse_options(large).anchors.size() == 5);
  auto dup = args; dup.insert(dup.end(), {"--from", "100"}); fails([&] { parse_options(dup); });
  auto bad = args; bad[3] = std::string(64, '0'); fails([&] { parse_options(bad); });
  o.db = t.dir("primary"); o.secondary = t.dir("secondary"); o.work = t.dir("work"); validate_paths(o);
  auto alias = t.path / "alias"; std::filesystem::create_directory_symlink(o.db, alias);
  o.secondary = alias; fails([&] { validate_paths(o); });
  o.secondary = o.db / "inside"; std::filesystem::create_directory(o.secondary); fails([&] { validate_paths(o); });
  auto list = t.path / "anchors";
  { std::ofstream f(list); f << "100 " << std::string(64, 'a') << ' ' << std::string(64, 'b') << '\n'
      << "100 " << std::string(64, 'c') << ' ' << std::string(64, 'd') << '\n'; }
  args.resize(6); args.insert(args.end(), {"--anchors-file", list.string()}); fails([&] { parse_options(args); });
}
void journal(Temp& t) {
  auto work = t.dir("journal");
  std::vector<AnchorRequest> plan{{100, {}, {}}, {101, {}, {}}, {102, {}, {}}};
  Commit first{100, "full-mc100", {"-1:all:100", "0:all:5"}, "{\"value\":1}\n"};
  {
    Progress p(work, "scope-A", plan, 1024, identity);
    p.commit(first); check(p.completed(100, "full-mc100"));
    fails([&] { p.completed(100, "fork-mc100"); });
    fails([&] { p.commit(first); });
    fails([&] { Progress simultaneous(work, "scope-A", plan, 1024, identity); });
  }
  {
    Progress p(work, "scope-A", plan, 1024, identity);
    check(p.completed_count() == 1 && !p.completed(101, "full-mc101"));
    // A real extraction exception never reaches commit; preserve the separately
    // verified snapshot, but the failed anchor must be retried on restart.
    try { throw std::runtime_error("missing historical config"); }
    catch (...) { p.failed(101, "{\"dataset\":\"validators\",\"count\":381}\n"); }
    check(!p.completed(101, "full-mc101") && p.completed_count() == 1);
    fails([&] { p.commit({101, "full-mc101", {"-1:all:101", "0:all:5"}, "{}\n"}); });
    fails([&] { p.commit({101, "full-mc101", {"0:all:6", "0:all:6"}, "{}\n"}); });
    fails([&] { p.commit({102, "full-mc102", {"-1:all:102"}, "{}\n"}); });
    check(p.completed_count() == 1);
  }
  {
    auto staging = work / "101.pending"; std::filesystem::create_directory(staging);
    { std::ofstream f(staging / "facts.ndjson"); f << "partial"; }
    Progress p(work, "scope-A", plan, 1024, identity);
    check(p.completed_count() == 1); p.commit({101, "full-mc101", {"-1:all:101", "0:all:6"}, "{}\n"});
    check(p.completed_count() == 2);
  }
  fails([&] { Progress wrong_scope(work, "scope-B", plan, 1024, identity); });
  { std::ofstream f(work / "101.committed/facts.ndjson", std::ios::app); f << "tampered"; }
  fails([&] { Progress corrupt(work, "scope-A", plan, 1024, identity); });
  auto gap = t.dir("gap");
  { Progress p(gap, "scope-A", plan, 1024, identity); p.commit(first); p.commit({101, "full-mc101", {"-1:all:101"}, "{}\n"}); }
  std::filesystem::remove_all(gap / "100.committed");
  fails([&] { Progress noncontiguous(gap, "scope-A", plan, 1024, identity); });
}
void frontier() {
  using Id = std::string;
  const std::set<Id> previous{"mc100", "parent", "unchanged"};
  const std::set<Id> next{"mc101", "left2", "right", "unchanged"};
  const std::map<Id, std::vector<Id>> split{
      {"mc101", {"mc100"}}, {"left", {"parent"}}, {"left2", {"left"}}, {"right", {"parent"}}};
  require_frontier(previous, next, split);
  auto missing = split; missing.erase("left"); fails([&] { require_frontier(previous, next, missing); });
  auto missing_child = split; missing_child.erase("right"); fails([&] { require_frontier(previous, next, missing_child); });
  auto phantom = split; phantom.emplace("phantom", std::vector<Id>{"parent"});
  fails([&] { require_frontier(previous, next, phantom); });
  auto old_tip = split; old_tip.emplace("unchanged", std::vector<Id>{"parent"});
  fails([&] { require_frontier(previous, next, old_tip); });
  std::map<Id, std::vector<Id>> merge{{"mc102", {"mc101"}}, {"merged", {"left2", "right"}}};
  require_frontier(next, std::set<Id>{"mc102", "merged", "unchanged"}, merge);
  merge["merged"] = {"left2", "left2"};
  fails([&] { require_frontier(next, std::set<Id>{"mc102", "merged", "unchanged"}, merge); });
}
}
int main() {
  try { Temp temp; options(temp); journal(temp); frontier(); std::cout << "runner options/resume/failure/duplicate-scope/frontier tests passed\n"; }
  catch (const std::exception& e) { std::cerr << e.what() << '\n'; return 1; }
}
