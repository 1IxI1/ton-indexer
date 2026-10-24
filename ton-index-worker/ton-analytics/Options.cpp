#include "Options.h"

#include <algorithm>
#include <fstream>
#include <limits>
#include <map>
#include <sstream>
#include <stdexcept>

namespace tonstat::runner {
void require(bool condition, const std::string& reason) {
  if (!condition) throw std::runtime_error(reason);
}
std::string lower(std::string value) {
  for (auto& c : value) if (c >= 'A' && c <= 'F') c += 'a' - 'A';
  return value;
}
bool hash_hex(const std::string& value) {
  return value.size() == 64 && value.find_first_not_of("0123456789abcdefABCDEF") == std::string::npos &&
         value.find_first_not_of('0') != std::string::npos;
}
namespace {
uint64_t number(const std::string& s, uint64_t max = UINT32_MAX) {
  require(!s.empty() && s.find_first_not_of("0123456789") == std::string::npos, "invalid unsigned integer");
  auto n = std::stoull(s);
  require(n <= max, "integer exceeds option limit");
  return n;
}
bool within(const std::filesystem::path& child, const std::filesystem::path& parent) {
  auto c = child.begin();
  for (const auto& p : parent) { if (c == child.end() || *c++ != p) return false; }
  return true;
}
std::filesystem::path safe_dir(const std::filesystem::path& path) {
  namespace fs = std::filesystem;
  require(!path.empty() && fs::is_directory(path), "directories must already exist");
  fs::path part;
  for (const auto& x : fs::absolute(path)) {
    part /= x;
    require(!fs::is_symlink(fs::symlink_status(part)), "symlink directory component is forbidden");
  }
  return fs::canonical(path);
}
} // namespace
void validate_paths(Options& o) {
  o.db = safe_dir(o.db); o.secondary = safe_dir(o.secondary); o.work = safe_dir(o.work);
  for (auto a : {o.db, o.secondary, o.work}) for (auto b : {o.db, o.secondary, o.work})
    if (a != b) require(!within(a, b), "DB, secondary and facts workdir must be disjoint");
  require(o.db != o.secondary && o.db != o.work && o.secondary != o.work, "directories overlap");
}
Options parse_options(const std::vector<std::string>& args) {
  Options o;
  std::map<std::string, std::string> values;
  for (size_t i = 0; i < args.size(); ++i) {
    auto key = args[i];
    require(key.starts_with("--"), "expected --option");
    std::string value;
    if (key == "--supply" || key == "--wallet-events" || key == "--nft-candidates") value = "1";
    else { require(i + 1 < args.size(), "option requires a value"); value = args[++i]; }
    require(values.emplace(key, value).second, "duplicate option: " + key);
  }
  auto take = [&](const std::string& key, std::string fallback = {}) {
    auto it = values.find(key);
    if (it == values.end()) return fallback;
    auto v = it->second; values.erase(it); return v;
  };
  o.db = take("--db-root"); o.secondary = take("--secondary-working-dir"); o.work = take("--work-dir");
  o.network = take("--network"); o.zero_root = lower(take("--zerostate-root")); o.zero_file = lower(take("--zerostate-file"));
  require(o.network == "mainnet" || o.network == "testnet", "network must be mainnet|testnet");
  require(hash_hex(o.zero_root) && hash_hex(o.zero_file), "pin both nonzero zerostate hashes");
  o.max_anchors = number(take("--max-anchors", "4"), 100000);
  o.max_blocks = number(take("--max-blocks", "256"), 4096);
  o.max_transactions = number(take("--max-transactions", "100000"), 1000000);
  o.max_aux = number(take("--max-aux", "256"), 4096);
  o.max_seconds = number(take("--max-seconds", "300"), 86400);
  o.anchor_time_from = number(take("--anchor-time-from", "1788220800"));
  o.anchor_time_to = number(take("--anchor-time-to", "1790812800"));
  require(o.anchor_time_from < o.anchor_time_to, "empty anchor time interval");
  o.max_output_bytes = number(take("--max-output-bytes", "67108864"), 1024ULL * 1024 * 1024);
  o.accounts_limit = number(take("--accounts-sample-limit", "0"), 1000000);
  o.supply = !take("--supply").empty(); o.wallet_events = !take("--wallet-events").empty();
  o.nft_candidates = !take("--nft-candidates").empty();
  require(o.max_anchors && o.max_blocks && o.max_transactions && o.max_aux && o.max_seconds && o.max_output_bytes,
          "budgets must be positive");
  auto list = take("--anchors-file"), from = take("--from"), to = take("--to");
  require(values.empty(), values.empty() ? "" : "unknown option: " + values.begin()->first);
  if (!list.empty()) {
    require(from.empty() && to.empty(), "anchor list and range are mutually exclusive");
    std::ifstream in(list); require(bool(in), "cannot open anchors file");
    std::string line;
    while (std::getline(in, line)) {
      require(line.size() <= 256, "anchor line exceeds limit");
      if (line.empty() || line.front() == '#') continue;
      std::istringstream row(line); std::string n, root, file, extra;
      require(bool(row >> n >> root >> file) && !(row >> extra), "anchor row: SEQNO ROOT_HEX FILE_HEX");
      require(hash_hex(root) && hash_hex(file), "anchor file requires full hashes");
      require(o.anchors.size() < o.max_anchors, "anchor list exceeds --max-anchors");
      o.anchors.push_back({static_cast<uint32_t>(number(n)), lower(root), lower(file)});
    }
    require(in.eof(), "anchors read failed");
  } else {
    require(!from.empty() && !to.empty(), "supply --from N --to M or --anchors-file FILE");
    auto a = number(from), b = number(to);
    require(a <= b && b - a < o.max_anchors, "range exceeds --max-anchors");
    for (auto n = a; n <= b; ++n) o.anchors.push_back({static_cast<uint32_t>(n), {}, {}});
  }
  require(!o.anchors.empty(), "empty anchor plan");
  uint32_t last = 0;
  for (const auto& a : o.anchors) {
    require(a.seqno >= 2 && a.seqno > last, "anchors must be strictly increasing, unique, and >=2");
    last = a.seqno;
  }
  return o;
}
std::string Options::scope() const {
  std::ostringstream s;
  s << kVersion << '\n' << network << '\n' << zero_root << '\n' << zero_file << '\n'
    << "supply=" << supply << ";wallets=" << wallet_events << ";nft=" << nft_candidates
    << ";accounts_sample=" << accounts_limit << '\n'
    << "blocks=" << max_blocks << ";tx=" << max_transactions << ";aux=" << max_aux
    << ";bytes=" << max_output_bytes << '\n';
  s << "anchor_time=[" << anchor_time_from << ',' << anchor_time_to << ")\n";
  for (const auto& a : anchors) s << a.seqno << ' ' << a.root << ' ' << a.file << '\n';
  return s.str();
}
} // namespace tonstat::runner
