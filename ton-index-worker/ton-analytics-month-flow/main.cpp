#include "../ton-analytics-core/AnchorEvidence.h"
#include "../ton-analytics-flow/Extractor.h"
#include "../ton-analytics/Frontier.h"
#include "../tondb-scanner/src/DbScanner.h"
#include "crypto/block/block-auto.h"
#include "crypto/block/block-parse.h"
#include "crypto/block/mc-config.h"
#include "td/actor/actor.h"
#include "td/actor/coro_utils.h"
#include "td/utils/crypto.h"
#include "td/utils/logging.h"
#include "td/utils/misc.h"
#include "validator/fabric.h"
#include <algorithm>
#include <chrono>
#include <csignal>
#include <deque>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <stdexcept>
#include <sys/file.h>
#include <vector>
#include <fcntl.h>
#include <unistd.h>

namespace mf {
namespace fs = std::filesystem;
#ifndef FLOW_SOURCE_SHA256
#error "CMake source fingerprint is required"
#endif
#ifndef FLOW_TON_REVISION
#error "Pinned TON revision is required"
#endif
using tonstat::runner::require;
using ton::BlockIdExt;
using ton::validator::MasterchainState;
using tonstat::core::NetworkPin;
struct Options {
  fs::path db, secondary, work;
  std::string network, zero_root, zero_file;
  uint32_t from{}, to{}, max_mc{64}, max_chunks{1}, prefetch{1}, max_blocks{256}, max_tx{100000}, max_aux{128}, max_seconds{300};
  uint64_t max_bytes{64 * 1024 * 1024};
};
std::string hex(const std::string& s) {
  require(s.size() == 64 && s.find_first_not_of("0123456789abcdefABCDEF") == std::string::npos, "invalid hash");
  std::string out = s;
  std::transform(out.begin(), out.end(), out.begin(), [](char c) { return c >= 'A' && c <= 'F' ? c + 'a' - 'A' : c; });
  return out;
}
uint64_t number(const std::string& s, uint64_t maximum) {
  require(!s.empty() && s.find_first_not_of("0123456789") == std::string::npos, "invalid number");
  auto n = std::stoull(s); require(n > 0 && n <= maximum, "option out of bounds"); return n;
}
fs::path directory(const std::string& p) {
  require(!p.empty() && fs::is_directory(p), "directory must already exist");
  fs::path walk;
  for (const auto& part : fs::absolute(p)) { walk /= part; require(!fs::is_symlink(fs::symlink_status(walk)), "symlink in directory path"); }
  return fs::canonical(p);
}
bool inside(const fs::path& a, const fs::path& b) {
  auto i = a.begin();
  for (auto part : b) { if (i == a.end() || *i++ != part) return false; }
  return true;
}
Options parse(int argc, char** argv) {
  std::map<std::string, std::string> args;
  for (int i = 1; i < argc; i += 2) {
    require(i + 1 < argc && std::string(argv[i]).starts_with("--") && args.emplace(argv[i], argv[i+1]).second,
            "options must be unique --key value pairs");
  }
  auto take = [&](std::string k, std::string d = {}) {
    auto it = args.find(k); if (it == args.end()) return d;
    auto result = it->second; args.erase(it); return result;
  };
  Options o;
  o.db = directory(take("--db-root")); o.secondary = directory(take("--secondary-work-dir")); o.work = directory(take("--workdir"));
  for (auto a : {o.db, o.secondary, o.work}) for (auto b : {o.db, o.secondary, o.work})
    if (a != b) require(!inside(a, b), "DB, secondary and output directories overlap");
  o.network = take("--network"); require(o.network == "mainnet" || o.network == "testnet", "unknown network");
  o.zero_root = hex(take("--zerostate-root")); o.zero_file = hex(take("--zerostate-file"));
  o.from = number(take("--from"), UINT32_MAX); o.to = number(take("--to"), UINT32_MAX);
  require(o.from < o.to, "--to must be exclusive and greater than --from");
  o.max_mc = number(take("--max-mc", "64"), 1024);
  o.max_chunks = number(take("--max-chunks", "1"), 65536);
  o.prefetch = number(take("--prefetch", "1"), 8);
  o.max_blocks = number(take("--max-blocks", "256"), 4096);
  o.max_tx = number(take("--max-transactions", "100000"), 1000000);
  o.max_aux = number(take("--max-aux", "128"), 4096);
  o.max_seconds = number(take("--max-seconds", "300"), 3600);
  o.max_bytes = number(take("--max-output-bytes", "67108864"), 1024ULL * 1024 * 1024);
  require(args.empty(), "unrecognized option");
  return o;
}
td::Bits256 bits(const std::string& s) {
  td::Bits256 b;
  auto decoded = td::hex_decode(s); require(decoded.is_ok(), "invalid hash encoding");
  b.as_slice().copy_from(decoded.move_as_ok()); return b;
}
std::string digest(const std::string& s) { return td::hex_encode(td::sha256(s)); }
std::string read_file(const fs::path& path, uint64_t limit) {
  require(!fs::is_symlink(fs::symlink_status(path)) && fs::is_regular_file(path) && fs::file_size(path) <= limit,
          "unsafe or oversized checkpoint");
  std::ifstream in(path, std::ios::binary); require(bool(in), "cannot read checkpoint");
  std::ostringstream out; out << in.rdbuf(); require(!in.bad(), "checkpoint read error"); return out.str();
}
void sync_directory(const fs::path& path) {
  int fd = open(path.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
  require(fd >= 0, "cannot open output directory"); bool ok = fsync(fd) == 0; close(fd); require(ok, "directory fsync failed");
}
void write_new(const fs::path& path, const std::string& data) {
  int fd = open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
  require(fd >= 0, "cannot create output file");
  size_t pos = 0;
  while (pos < data.size()) { auto n = write(fd, data.data()+pos, data.size()-pos); require(n > 0, "output write failed"); pos += n; }
  bool ok = fsync(fd) == 0; close(fd); require(ok, "output fsync failed");
}
struct Checkpoints {
  Options o; int lock{-1}; uint32_t next; std::string previous;
  explicit Checkpoints(Options opt) : o(std::move(opt)), next(o.from) {
    lock = open((o.work / "flow.lock").c_str(), O_RDWR | O_CREAT | O_NOFOLLOW, 0600);
    require(lock >= 0 && flock(lock, LOCK_EX | LOCK_NB) == 0, "flow workdir already locked");
    std::string scope = "ton-flow-month-v1\n" + o.network + "\n" + o.zero_root + "\n" + o.zero_file +
      "\n" + std::to_string(o.from) + " " + std::to_string(o.to) + "\n" +
      FLOW_SOURCE_SHA256 "/" FLOW_TON_REVISION "\n";
    auto path = o.work / "scope.txt";
    if (fs::exists(path)) require(read_file(path, 2048) == scope, "checkpoint scope mismatch");
    else { write_new(path, scope); sync_directory(o.work); }
    // Reject unknown/partial commit names, gaps, hash conflicts, and altered chunks.
    for (const auto& p : fs::directory_iterator(o.work)) {
      auto name = p.path().filename().string();
      if (name == "flow.lock" || name == "scope.txt") continue;
      require(name.starts_with("chunk-") && name.ends_with(".ndjson") && p.is_regular_file() && !p.is_symlink(),
              "foreign, interrupted or unsafe checkpoint path");
    }
    std::set<fs::path> claimed;
    for (auto n = o.from; n < o.to;) {
      auto prefix = "chunk-" + std::to_string(n) + "-";
      fs::path found;
      for (const auto& p : fs::directory_iterator(o.work)) {
        if (p.path().filename().string().starts_with(prefix)) {
          require(found.empty(), "overlapping chunks"); found = p.path();
        }
      }
      if (found.empty()) break;
      auto name = found.filename().string();
      auto boundary = name.find('-', 6);
      require(boundary != std::string::npos && name.ends_with(".ndjson"), "invalid chunk name");
      auto end = number(name.substr(boundary+1, name.size()-boundary-8), UINT32_MAX);
      require(end > n && end <= o.to, "chunk exceeds scope");
      auto text = read_file(found, o.max_bytes);
      // Receipt is the last line. It commits the SHA of all previous lines and the prior-chunk fence.
      auto marker = text.rfind("{\"receipt\":"); require(marker != std::string::npos, "missing receipt");
      auto body = text.substr(0, marker), tail = text.substr(marker);
      require(tail == "{\"receipt\":\"" + digest(body) + "\",\"previous\":\"" + previous + "\"}\n",
              "chunk checksum/fence mismatch");
      previous = digest(text); next = static_cast<uint32_t>(end); n = next;
      claimed.insert(found);
    }
    for (const auto& p : fs::directory_iterator(o.work)) {
      auto name = p.path().filename().string();
      if (name.starts_with("chunk-")) {
        auto sep = name.find('-', 6); require(sep != std::string::npos, "invalid chunk start");
        auto start = number(name.substr(6, sep-6), UINT32_MAX);
        require(start < next && claimed.count(p.path()), "checkpoint gap or unclaimed chunk");
      }
    }
  }
  ~Checkpoints() { if (lock >= 0) close(lock); }
  void commit(uint32_t end, const std::string& body) {
    require(end > next && end <= o.to && body.size() + 256 <= o.max_bytes, "chunk bounds exceeded");
    auto text = body + "{\"receipt\":\"" + digest(body) + "\",\"previous\":\"" + previous + "\"}\n";
    auto target = o.work / ("chunk-" + std::to_string(next) + "-" + std::to_string(end) + ".ndjson");
    require(!fs::exists(target), "immutable chunk conflict");
    auto pending = o.work / "chunk.pending";
    require(!fs::exists(pending), "interrupted chunk needs explicit inspection");
    write_new(pending, text); fs::rename(pending, target); sync_directory(o.work);
    previous = digest(text); next = end;
  }
};
template<class T> T needed(td::Result<T> r, const char* context) {
  if (r.is_error()) throw std::runtime_error(std::string(context) + ": " + r.move_as_error().to_string());
  return r.move_as_ok();
}
td::Ref<MasterchainState> typed(const schema::BlockDataState& b) {
  auto value = needed(ton::validator::create_shard_state(b.handle->id(), b.block_state), "MC state");
  td::Ref<MasterchainState> mc{value}; require(mc.not_null(), "not MC state"); return mc;
}
std::set<BlockIdExt> tips(const schema::BlockDataState& b) {
  block::gen::ShardStateUnsplit::Record state; block::gen::McStateExtra::Record extra;
  require(tlb::unpack_cell(b.block_state, state) && state.custom.not_null() &&
    tlb::unpack_cell(state.custom->prefetch_ref(), extra) &&
    block::gen::t_ShardHashes.validate_csr(1 << 20, extra.shard_hashes), "invalid MC shard hashes");
  std::set<BlockIdExt> result;
  for (const auto& shard : typed(b)->get_shards())
    require(result.insert(shard->top_block_id()).second, "duplicate shard tip");
  return result;
}
void frontier(const tonstat::core::MaterializedAnchor& view, const schema::BlockDataState& prev, size_t limit) {
  auto old = tips(prev), expected = tips(view.mc()); old.insert(prev.handle->id()); expected.insert(view.mc().handle->id());
  std::set<BlockIdExt> inserted;
  std::map<BlockIdExt, std::vector<BlockIdExt>> pending, children;
  require(view.first_included().size() <= limit, "first inclusion block limit");
  for (const auto& b : view.first_included()) {
    auto id = b.handle->id(); require(!old.count(id) && inserted.insert(id).second, "duplicate or old block");
    auto h = needed(block::get_block_header_info(b.block_data->root_cell(), id), "raw predecessor");
    require(h.prev.size() > 0 && h.prev.size() <= 2, "invalid predecessor arity");
    std::set<BlockIdExt> distinct;
    for (const auto& p : h.prev) {
      require(p.is_valid_full() && p.id.workchain == id.id.workchain && p.id.seqno < id.id.seqno && distinct.insert(p).second,
              "invalid predecessor"); children[p].push_back(id);
    }
    if (id.is_masterchain()) require(h.prev.size() == 1 && h.prev.front() == prev.handle->id(), "MC predecessor mismatch");
    else if (h.prev.size() == 2)
      require(!h.after_split && ton::shard_is_parent(id.id.shard, h.prev[0].id.shard) &&
        ton::shard_is_parent(id.id.shard, h.prev[1].id.shard) && ton::shard_is_sibling(h.prev[0].id.shard, h.prev[1].id.shard), "invalid merge");
    else require(h.after_split ? ton::shard_is_parent(h.prev[0].id.shard, id.id.shard) :
      h.prev[0].id.shard == id.id.shard, "invalid split or ordinary predecessor");
    pending.emplace(id, std::move(h.prev));
  }
  for (const auto& [p, kids] : children) if (kids.size() > 1)
    require(kids.size() == 2 && ton::shard_is_parent(p.id.shard, kids[0].id.shard) &&
      ton::shard_is_parent(p.id.shard, kids[1].id.shard) && ton::shard_is_sibling(kids[0].id.shard, kids[1].id.shard),
      "invalid split children");
  tonstat::runner::require_frontier(old, expected, std::move(pending));
}
std::string quote(const std::string& s) {
  require(s.find_first_of("\"\\\r\n") == std::string::npos, "unsafe JSON field"); return "\"" + s + "\"";
}
std::string id_json(const BlockIdExt& id) {
  return "{\"wc\":" + std::to_string(id.id.workchain) + ",\"shard\":" + quote(std::to_string(id.id.shard)) +
      ",\"seqno\":" + std::to_string(id.id.seqno) + ",\"root\":" + quote(id.root_hash.to_hex()) +
      ",\"file\":" + quote(id.file_hash.to_hex()) + "}";
}
BlockIdExt native(const ton_analytics::flow::BlockId& id) {
  return {id.workchain, id.shard, id.seqno, bits(id.root_hash), bits(id.file_hash)};
}
std::string day(uint32_t t) {
  constexpr uint32_t first = 1788220800, end = 1790812800;
  if (t < first) return "before";
  if (t >= end) return "after";
  return std::to_string((t - first) / 86400); // UTC day index 0..29, based ONLY on raw block gen_utime
}
td::RefInt256 integer(const std::string& s) {
  require(!s.empty() && s.find_first_not_of("0123456789") == std::string::npos, "invalid money decimal");
  auto n = td::dec_string_to_int256(s); require(n.not_null() && n->is_valid() && td::sgn(n) >= 0, "money overflow"); return n;
}
void add(td::RefInt256& total, const std::string& decimal) {
  total += integer(decimal); require(total.not_null() && total->is_valid(), "daily money overflow");
}
struct Sum {
  td::RefInt256 fees = td::make_refint(0), created = td::make_refint(0), burned = td::make_refint(0), sink = td::make_refint(0);
  uint64_t blocks{}, txs{}, v1{}, sink_count{};
};
std::string sums_json(const std::map<std::string, Sum>& values, uint32_t mc) {
  std::string out;
  for (const auto& [date, x] : values) {
    out += "{\"kind\":\"daily\",\"status\":\"verified_local_archive_fragment\",\"mc\":" + std::to_string(mc) + ",\"day\":" + quote(date) +
      ",\"blocks\":" + std::to_string(x.blocks) + ",\"transactions\":" + std::to_string(x.txs) +
      ",\"gross_fees_nanoton\":" + x.fees->to_dec_string() + ",\"created_nanoton\":" + x.created->to_dec_string() +
      ",\"burned_v2_nanoton\":" + x.burned->to_dec_string() + ",\"burned_v1_unknown_blocks\":" + std::to_string(x.v1) +
      ",\"zero_sink_sent_nanoton\":" + x.sink->to_dec_string() +
      ",\"zero_sink_sent_count\":" + std::to_string(x.sink_count) + ",\"zero_sink_delivered_nanoton\":null}\n";
  }
  return out;
}
void fail_status(const std::shared_ptr<const tonstat::core::AnchorEvidence>& e, const Options& o) {
  std::string issues;
  if (e) for (const auto& issue : e->issues) issues += issue.code + ":" + issue.detail + ";";
  require(e && e->status == tonstat::core::Status::verified_local_archive && e->network == o.network &&
    e->snapshot_integrity_checked && e->continuity_status == tonstat::core::Status::verified_local_archive,
    "raw anchor/continuity not verified: " + issues);
}
td::actor::Task<schema::BlockDataState> auxiliary(td::actor::ActorId<DbScanner> scanner, BlockIdExt id,
                                                   NetworkPin pin, Options o) {
  auto r = co_await td::actor::ask(scanner, &DbScanner::fetch_block_by_id, id).wrap();
  if (r.is_error()) co_return r.move_as_error();
  auto entry = r.move_as_ok();
  auto proof = tonstat::core::verify_auxiliary_mc(entry, id, pin);
  if (!proof || proof->status != tonstat::core::Status::verified_local_archive || proof->network != o.network)
    co_return td::Status::Error("historical MC state/BoC not verified");
  co_return entry;
}
td::actor::Task<td::Unit> run(td::actor::ActorId<DbScanner> scanner, Options o, Checkpoints& checkpoints) {
  try {
    NetworkPin pin{{ton::masterchainId, ton::shardIdAll, 0, bits(o.zero_root), bits(o.zero_file)}};
    // MC0 is a zerostate, not an ordinary seqno-indexed archived block.
    // verify_anchor/verify_auxiliary_mc bind this trusted full network pin to
    // the decoded historical MC post-state without an MC0-by-seqno lookup.
    auto rr = co_await td::actor::ask(scanner, &DbScanner::get_cell_db_reader).wrap();
    auto reader = needed(std::move(rr), "secondary cell reader"); require(bool(reader), "no cell reader");
    const auto begun = std::chrono::steady_clock::now();
    uint32_t committed = 0;
    // Retain only the immediately preceding independently verified MC input.
    // verify_anchor checks its raw BoC/state/continuity again on every use.
    std::optional<schema::BlockDataState> last_verified_mc;
    while (checkpoints.next < o.to && committed < o.max_chunks) {
      // Leave one chunk's time to close cleanly; the hard alarm remains the
      // fail-closed bound for a slow or blocked individual archive request.
      if (committed && std::chrono::steady_clock::now() - begun >=
                           std::chrono::seconds(o.max_seconds > 60 ? o.max_seconds - 60 : 0)) break;
      std::string body;
      auto stop = std::min<uint64_t>(o.to, uint64_t(checkpoints.next) + o.max_mc);
      // Match the production scheduler's bounded fetch concurrency while
      // verifying/serializing/committing strictly in MC seqno order. A child
      // IndexQuery (not this actor) owns each in-flight scanner fetch.
      using Fetch = td::actor::StartedTask<schema::MasterchainBlockDataState>;
      std::deque<std::pair<uint32_t, Fetch>> pending;
      uint32_t next_fetch = checkpoints.next;
      for (uint32_t seq = checkpoints.next; seq < stop; ++seq) {
      while (next_fetch < stop && pending.size() < o.prefetch) {
        pending.emplace_back(next_fetch, td::actor::ask(scanner, &DbScanner::fetch_seqno, next_fetch));
        ++next_fetch;
      }
      require(!pending.empty() && pending.front().first == seq, "scanner prefetch order changed");
      auto request = std::move(pending.front().second);
      pending.pop_front();
      auto fr = co_await std::move(request).wrap();
      auto data = needed(std::move(fr), "first-included blocks");
      require(!data.shard_blocks_.empty(), "selected MC snapshot is missing");
      const auto& mc = data.shard_blocks_.front();
      require(mc.handle && mc.block_data.not_null() && mc.block_state.not_null(),
              "selected MC handle/BoC/post-state missing");
      auto id = mc.handle->id();
      require(id.is_masterchain() && id.id.seqno == seq && mc.block_data->block_id() == id,
              "selected MC full ID differs from requested seqno or raw archive data");
      require(data.shard_blocks_.size() <= o.max_blocks && data.shard_blocks_diff_.size() <= o.max_blocks,
              "raw block budget exceeded");
      // The exact raw MC input is already in fetch_seqno. Core verifies its
      // original BoC SHA, root, network and post-state below; no second DB
      // fetch is needed merely to obtain the same handle/BoC/state.
      auto h = needed(block::get_block_header_info(mc.block_data->root_cell(), id), "MC header");
      require(h.prev.size() == 1 && h.prev.front().is_valid_full() &&
                  h.prev.front().id.seqno + 1 == seq, "adjacent full MC predecessor absent");
      schema::BlockDataState prev;
      if (last_verified_mc && last_verified_mc->handle &&
          last_verified_mc->handle->id() == h.prev.front()) {
        prev = *last_verified_mc;
      } else {
        auto pr = co_await auxiliary(scanner, h.prev.front(), pin, o).wrap();
        prev = needed(std::move(pr), "verified previous MC");
      }
      auto verified = tonstat::core::verify_anchor(data, id, pin, {}, &prev, reader);
      fail_status(verified.evidence, o); require(bool(verified.view), "no retained raw snapshot");
      auto view = verified.view;
      frontier(*view, prev, o.max_blocks);
      auto state = typed(view->mc());
      struct Config { uint32_t version; std::string state_hash, config8_hash; };
      std::map<BlockIdExt, Config> by_ref;
      std::map<BlockIdExt, uint32_t> versions;
      std::map<BlockIdExt, BlockIdExt> source_refs;
      for (const auto& b : view->first_included()) {
        auto b_id = b.handle->id();
        auto bh = needed(block::get_block_header_info(b.block_data->root_cell(), b_id), "execution MC reference");
        auto ref = bh.mc_blkid;
        BlockIdExt ancestor;
        require(ref.is_masterchain() && ref.id.seqno < id.id.seqno &&
          state->get_old_mc_block_id(ref.id.seqno, ancestor) && ancestor == ref,
          "execution MC not in canonical ancestry");
        if (!by_ref.count(ref)) {
          require(by_ref.size() < o.max_aux, "historical MC reference cap");
          schema::BlockDataState cfg_source;
          if (ref == prev.handle->id()) cfg_source = prev;
          else {
            auto ar = co_await auxiliary(scanner, ref, pin, o).wrap();
            cfg_source = needed(std::move(ar), "historical config MC");
          }
          auto cfg = needed(block::ConfigInfo::extract_config(cfg_source.block_state, ref,
              block::ConfigInfo::needCapabilities), "historical config");
          require(cfg->get_config_param(8).not_null() && cfg->get_global_version() >= 0,
                  "historical config #8 unavailable");
          by_ref.emplace(ref, Config{static_cast<uint32_t>(cfg->get_global_version()),
            cfg_source.block_state->get_hash().to_hex(), cfg->get_config_param(8)->get_hash().to_hex()});
        }
        versions.emplace(b_id, by_ref.at(ref).version);
        source_refs.emplace(b_id, ref);
      }
      ton_analytics::flow::Limits limits;
      limits.max_blocks = o.max_blocks; limits.max_transactions_per_block = o.max_tx;
      limits.max_accounts_per_block = o.max_tx; limits.max_messages_per_block = static_cast<size_t>(o.max_tx) * 256;
      limits.max_zero_sink_sends_per_batch = o.max_tx;
      auto extracted = ton_analytics::flow::extract(view->snapshot(), [&](const auto& b) -> std::optional<uint32_t> {
        auto it = versions.find(native(b)); return it == versions.end() ? std::nullopt : std::make_optional(it->second);
      }, limits);
      require(native(extracted.mc_id) == id, "extractor MC mismatch");
      std::map<std::string, Sum> totals;
      uint64_t transactions = 0;
      std::string rows;
      // Scanner inclusion order can depend on asynchronous shard traversal.
      // Sort by the immutable full block ID so equal evidence always produces
      // byte-identical chunk bodies and chained receipts across restarts.
      std::vector<const ton_analytics::flow::BlockFact*> ordered_blocks;
      ordered_blocks.reserve(extracted.blocks.size());
      for (const auto& b : extracted.blocks) ordered_blocks.push_back(&b);
      std::sort(ordered_blocks.begin(), ordered_blocks.end(), [](const auto* a, const auto* b) {
        return native(a->id) < native(b->id);
      });
      for (const auto* entry : ordered_blocks) {
        const auto& b = *entry;
        auto ref = source_refs.at(native(b.id));
        auto date = day(b.gen_utime);
        auto& sum = totals[date];
        require(sum.blocks < UINT64_MAX && sum.txs <= UINT64_MAX - b.tx_count &&
          sum.sink_count <= UINT64_MAX - b.zero_sink_sent_count && b.tx_count <= o.max_tx &&
          transactions <= o.max_tx - b.tx_count && b.gen_utime <= extracted.mc_gen_utime,
          "counter overflow or MC transaction cap");
        ++sum.blocks; sum.txs += b.tx_count; sum.sink_count += b.zero_sink_sent_count; transactions += b.tx_count;
        add(sum.fees, b.gross_fees_nanoton); add(sum.created, b.created_nanoton); add(sum.sink, b.zero_sink_sent_nanoton);
        if (b.burned_nanoton) add(sum.burned, *b.burned_nanoton); else ++sum.v1;
        require(b.minted_grams_nanoton == "0", "unexpected minted grams");
        rows += "{\"kind\":\"block\",\"id\":" + id_json(native(b.id)) + ",\"first_included_by\":" + id_json(id) +
          ",\"source_gen_utime\":" + std::to_string(b.gen_utime) + ",\"mc_inclusion_utime\":" +
          std::to_string(b.mc_inclusion_utime) + ",\"day\":" + quote(date) +
          ",\"config_mc\":" + id_json(ref) + ",\"config_state_root\":" + quote(by_ref.at(ref).state_hash) +
          ",\"config8_hash\":" + quote(by_ref.at(ref).config8_hash) +
          ",\"config_version\":" + std::to_string(b.applied_global_version) +
          ",\"poststate_verified\":true,\"original_boc_sha256_verified\":true}\n";
      }
      body += "{\"kind\":\"mc\",\"id\":" + id_json(id) + ",\"previous\":" + id_json(prev.handle->id()) +
        ",\"gen_utime\":" + std::to_string(extracted.mc_gen_utime) +
        ",\"verified_first_included\":" + std::to_string(extracted.blocks.size()) +
        ",\"frontier_verified\":true,\"network\":" + quote(o.network) + "}\n" + rows + sums_json(totals, seq);
      require(body.size() + 256 <= o.max_bytes, "output chunk byte limit");
      last_verified_mc = view->mc();
      }
      require(pending.empty() && next_fetch == stop, "scanner prefetch did not drain");
      if (stop > checkpoints.next) checkpoints.commit(static_cast<uint32_t>(stop), body);
      ++committed;
      std::cerr << "committed through MC (exclusive) " << stop
                << "; reader retained, next checkpoint in same process\n";
    }
    std::cerr << "checkpointed through MC (exclusive) " << checkpoints.next
              << "; resume with same scope/workdir if before requested --to\n";
    co_return td::Unit();
  } catch (const vm::VmError& e) { co_return e.as_status("month flow raw decode: "); }
  catch (const std::exception& e) { co_return td::Status::Error(td::Slice(e.what())); }
}
void alarm_handler(int) {
  constexpr char message[] = "month flow wall limit reached; current chunk not committed\n";
  (void)write(STDERR_FILENO, message, sizeof(message)-1); _exit(1);
}
} // namespace mf

int main(int argc, char** argv) {
  try {
    auto o = mf::parse(argc, argv);
    mf::Checkpoints checkpoints(o);
    if (checkpoints.next == o.to) { std::cerr << "all requested MC chunks already committed\n"; return 0; }
    std::signal(SIGALRM, mf::alarm_handler); alarm(o.max_seconds);
    SET_VERBOSITY_LEVEL(verbosity_WARNING);
    td::actor::Scheduler scheduler({2});
    td::actor::ActorOwn<DbScanner> scanner;
    auto status = std::make_shared<int>(1);
    auto watcher = td::create_shared_destructor([] { td::actor::SchedulerContext::get().stop(); });
    scheduler.run_in_context([&, watcher = std::move(watcher)]() mutable {
      scanner = td::actor::create_actor<DbScanner>("month-flow-secondary", o.db.string(), dbs_secondary,
        std::make_optional(o.secondary.string()), static_cast<float>(o.max_seconds + 60), false);
      auto done = td::PromiseCreator::lambda([watcher = std::move(watcher), status](td::Result<td::Unit> result) {
        if (result.is_error()) std::cerr << "month flow unresolved: " << result.move_as_error().to_string() << '\n';
        else *status = 0;
      });
      td::connect(std::move(done), mf::run(scanner.get(), o, checkpoints).start());
    });
    scheduler.run(); alarm(0); return *status;
  } catch (const std::exception& e) {
    std::cerr << "month flow: " << e.what() << '\n'; return 2;
  }
}
