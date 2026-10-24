#include "../tondb-scanner/src/DbScanner.h"
#include "crypto/block/block-auto.h"
#include "crypto/block/block-parse.h"
#include "crypto/block/block.h"
#include "crypto/vm/cells/MerkleUpdate.h"
#include "common/checksum.h"
#include "td/actor/actor.h"
#include "td/actor/coro_utils.h"
#include "td/utils/crypto.h"
#include "td/utils/logging.h"
#include "validator/interfaces/block.h"
#include <algorithm>
#include <chrono>
#include <csignal>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <stdexcept>
#include <sys/file.h>
#include <sys/resource.h>
#include <fcntl.h>
#include <unistd.h>

namespace burn {
namespace fs = std::filesystem;
using ton::BlockIdExt;
void need(bool ok, const std::string& why) { if (!ok) throw std::runtime_error(why); }
std::string lower(std::string value) {
  std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
    return c >= 'A' && c <= 'F' ? c + ('a' - 'A') : c;
  });
  return value;
}
template <class T> T ok(td::Result<T> value, const char* what) {
  if (value.is_error()) throw std::runtime_error(std::string(what) + ": " + value.move_as_error().to_string());
  return value.move_as_ok();
}
uint64_t number(const std::string& s, uint64_t max) {
  need(!s.empty() && s.find_first_not_of("0123456789") == std::string::npos, "invalid numeric option");
  auto n = std::stoull(s); need(n > 0 && n <= max, "numeric option out of range"); return n;
}
std::string hash(const std::string& s) {
  need(s.size() == 64 && s.find_first_not_of("0123456789abcdef") == std::string::npos, "noncanonical hex hash");
  return s;
}
td::Bits256 bits(const std::string& hex) {
  auto decoded = ok(td::hex_decode(hash(hex)), "hex hash");
  td::Bits256 result; result.as_slice().copy_from(decoded); return result;
}
std::string digest(const std::string& s) { return lower(td::hex_encode(td::sha256(s))); }
std::string quote(const std::string& s) {
  need(s.find_first_of("\"\\\r\n") == std::string::npos, "unsafe JSON string"); return "\"" + s + "\"";
}
std::string json_id(const BlockIdExt& id) {
  return "{\"wc\":-1,\"shard\":\"" + std::to_string(id.id.shard) + "\",\"seqno\":" +
    std::to_string(id.id.seqno) + ",\"root\":\"" + lower(id.root_hash.to_hex()) + "\",\"file\":\"" +
    lower(id.file_hash.to_hex()) + "\"}";
}
BlockIdExt mc(uint32_t seq, const std::string& root, const std::string& file) {
  return {ton::masterchainId, ton::shardIdAll, seq, bits(root), bits(file)};
}
struct Pin { std::string date; uint32_t utc; BlockIdExt prev, first; };
struct Pins { std::string anchors_sha, v3_sha, text_sha; std::vector<Pin> days; };
Pins parse_pins(const std::string& text) {
  Pins pins; pins.text_sha = digest(text); std::istringstream in(text), header;
  std::string line, tag, extra;
  need(bool(std::getline(in, line)), "missing pins header"); header.str(line);
  need(bool(header >> tag >> pins.anchors_sha >> pins.v3_sha) && !(header >> extra) &&
    tag == "mc-burn-pins-v1", "invalid pins header"); hash(pins.anchors_sha); hash(pins.v3_sha);
  while (std::getline(in, line)) {
    std::istringstream row(line); Pin p;
    std::string utc, before, after, pr, pf, nr, nf;
    need(bool(row >> p.date >> utc >> before >> pr >> pf >> after >> nr >> nf) && !(row >> extra),
         "invalid pins row");
    p.utc = number(utc, UINT32_MAX);
    p.prev = mc(number(before, UINT32_MAX), pr, pf); p.first = mc(number(after, UINT32_MAX), nr, nf);
    need(p.prev.id.seqno + 1 == p.first.id.seqno, "nonadjacent midnight pair");
    need(p.date == (pins.days.empty() ? "2026-09-01" : pins.days.size() == 30 ? "2026-10-01" :
      std::string("2026-09-") + (pins.days.size() + 1 < 10 ? "0" : "") + std::to_string(pins.days.size() + 1)),
      "nonconsecutive midnight date");
    need(p.utc == 1788220800u + pins.days.size() * 86400u, "wrong UTC midnight");
    if (!pins.days.empty()) need(p.prev.id.seqno + 1 == p.first.id.seqno &&
      pins.days.back().first.id.seqno < p.first.id.seqno, "nonmonotonic pinned MC IDs");
    pins.days.push_back(p);
  }
  need(pins.days.size() == 31 && pins.days.front().first.id.seqno == 89799586 &&
    pins.days.back().prev.id.seqno == 96135400 && pins.days.back().first.id.seqno == 96135401,
    "pins do not cover exact September interval");
  return pins;
}
fs::path directory(const std::string& s) {
  need(!s.empty() && fs::is_directory(s), "directory must exist");
  fs::path cur;
  for (auto& part : fs::absolute(s)) { cur /= part; need(!fs::is_symlink(fs::symlink_status(cur)), "symlink directory"); }
  return fs::canonical(s);
}
bool prefix(const fs::path& a, const fs::path& b) {
  auto it = a.begin();
  for (auto& part : b) if (it == a.end() || *it++ != part) return false;
  return true;
}
std::string read(const fs::path& path, uint64_t limit) {
  need(!fs::is_symlink(fs::symlink_status(path)) && fs::is_regular_file(path) && fs::file_size(path) <= limit,
       "unsafe or oversized input file");
  std::ifstream stream(path, std::ios::binary); need(bool(stream), "cannot open input file");
  std::ostringstream text; text << stream.rdbuf(); need(!stream.bad(), "input read failed"); return text.str();
}
struct Options {
  fs::path db, secondary, work; Pins pins;
  uint32_t from{}, to{}, max_mc{128}, max_chunks{1}, max_seconds{300};
  uint64_t max_output{16*1024*1024}, max_rss_mib{4096}, max_nofile{1048576};
};
Options parse(int argc, char** argv) {
  std::map<std::string,std::string> args;
  for (int i=1; i<argc; i+=2) need(i+1<argc && std::string(argv[i]).starts_with("--") &&
    args.emplace(argv[i], argv[i+1]).second, "duplicate, odd, or malformed options");
  auto take = [&](std::string key, std::string fallback = {}) {
    auto it = args.find(key); if (it == args.end()) return fallback;
    auto v = it->second; args.erase(it); return v;
  };
  Options o;
  o.db = directory(take("--db-root")); o.secondary = directory(take("--secondary-work-dir"));
  o.work = directory(take("--workdir"));
  need(!prefix(o.db,o.secondary) && !prefix(o.secondary,o.db) && !prefix(o.db,o.work) &&
    !prefix(o.work,o.db) && !prefix(o.secondary,o.work) && !prefix(o.work,o.secondary), "overlapping paths");
  auto pin_file = take("--pins"); need(!pin_file.empty(), "missing --pins");
  o.pins = parse_pins(read(pin_file, 16384));
  need(take("--network") == "mainnet", "only pinned mainnet is supported");
  need(take("--zerostate-root") == "17a3a92992aabea785a7a090985a265cd31f323d849da51239737e321fb05569" &&
    take("--zerostate-file") == "5e994fcf4d425c0a6ce6a792594b7173205f740a39cd56f537defd28b48a0f6e",
    "not published mainnet MC0 root/file pin");
  o.from = number(take("--from"), UINT32_MAX); o.to = number(take("--to"), UINT32_MAX);
  need(o.from >= 89799586 && o.from < o.to && o.to <= 96135401, "range outside September MC inclusion");
  o.max_mc = number(take("--max-mc", "128"), 1024);
  o.max_chunks = number(take("--max-chunks", "1"), 100000);
  o.max_seconds = number(take("--max-seconds", "300"), 86400);
  o.max_output = number(take("--max-output-bytes", "16777216"), 64*1024*1024);
  o.max_rss_mib = number(take("--max-rss-mib", "4096"), 65536);
  o.max_nofile = number(take("--max-nofile", "1048576"), 1048576);
  need(o.max_nofile >= 65536, "archived CellDB needs at least 65536 open files");
  need(args.empty(), "unknown option"); return o;
}
void sync_dir(const fs::path& p) {
  int fd = open(p.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
  need(fd>=0, "cannot open output directory"); bool good = fsync(fd)==0; close(fd); need(good, "directory fsync");
}
void write_new(const fs::path& path, const std::string& data) {
  int fd = open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600); need(fd>=0, "file already exists");
  size_t i=0; while (i<data.size()) { auto n=write(fd,data.data()+i,data.size()-i); need(n>0,"write error"); i+=n; }
  bool good = fsync(fd)==0; close(fd); need(good,"file fsync");
}
struct Checkpoints {
  const Options& o; int lock{-1}; uint32_t next; std::string previous;
  explicit Checkpoints(const Options& options) : o(options), next(o.from) {
    lock = open((o.work / "mc-burn.lock").c_str(), O_CREAT|O_RDWR|O_NOFOLLOW, 0600);
    need(lock>=0 && flock(lock, LOCK_EX|LOCK_NB)==0, "mc burn workdir locked");
    auto scope = "mc-burn-v1 mainnet " + o.pins.text_sha + " " + o.pins.anchors_sha + " " + o.pins.v3_sha +
      " " + std::to_string(o.from) + " " + std::to_string(o.to) + " " MC_BURN_SOURCE_SHA " " MC_BURN_TON_REV "\n";
    auto path = o.work / "scope.txt";
    if (fs::exists(path)) need(read(path,2048)==scope,"checkpoint scope, pins or source mismatch");
    else { write_new(path,scope); sync_dir(o.work); }
    std::set<std::string> seen;
    for (const auto& entry: fs::directory_iterator(o.work)) {
      auto name=entry.path().filename().string();
      if (name=="scope.txt" || name=="mc-burn.lock") continue;
      need(name.starts_with("chunk-") && name.ends_with(".ndjson") && !entry.is_symlink() &&
        entry.is_regular_file(), "foreign or partial checkpoint; inspect before resuming");
      need(seen.insert(name).second,"duplicate checkpoint");
    }
    while (next < o.to) {
      std::string start = "chunk-" + std::to_string(next) + "-";
      std::optional<fs::path> found;
      for (const auto& entry: fs::directory_iterator(o.work)) {
        if (entry.path().filename().string().starts_with(start)) {
          need(!found,"overlapping chunks"); found=entry.path();
        }
      }
      if (!found) break;
      auto name=found->filename().string();
      auto end=number(name.substr(start.size(),name.size()-start.size()-8),UINT32_MAX);
      need(end>next && end<=o.to && end-next<=o.max_mc,"invalid checkpoint range");
      auto text=read(*found,o.max_output);
      auto pos=text.rfind("{\"receipt\":"); need(pos!=std::string::npos,"missing receipt");
      auto body=text.substr(0,pos);
      need(text.substr(pos)=="{\"receipt\":\""+digest(body)+"\",\"previous\":\""+previous+"\"}\n",
           "checksum chain mismatch");
      previous=digest(text); next=end; seen.erase(name);
    }
    need(seen.empty(),"checkpoint gap, duplicate or out-of-scope chunk");
  }
  ~Checkpoints() { if (lock>=0) close(lock); }
  void commit(uint32_t end, const std::string& body) {
    need(end>next && end<=o.to && end-next<=o.max_mc && body.size()+256<=o.max_output,"chunk exceeded limits");
    auto text=body+"{\"receipt\":\""+digest(body)+"\",\"previous\":\""+previous+"\"}\n";
    auto pending=o.work/"chunk.pending";
    need(!fs::exists(pending),"interrupted pending file; inspect before resuming");
    auto target=o.work/("chunk-"+std::to_string(next)+"-"+std::to_string(end)+".ndjson");
    need(!fs::exists(target),"immutable chunk already exists");
    write_new(pending,text); fs::rename(pending,target); sync_dir(o.work);
    previous=digest(text); next=end;
  }
};
void budgets(const Options& o) {
  rusage usage{}; need(getrusage(RUSAGE_SELF,&usage)==0,"getrusage failed");
#ifdef __APPLE__
  uint64_t rss=usage.ru_maxrss;
#else
  uint64_t rss=uint64_t(usage.ru_maxrss)*1024;
#endif
  need(rss <= o.max_rss_mib*1024*1024,"RSS cap exceeded; current chunk uncommitted");
}
struct Record {
  BlockIdExt id, previous; uint32_t utime{};
  std::string old_state, new_state;
  std::optional<std::string> burned;
};
td::Ref<vm::Cell> verify_original_boc(const BlockIdExt& id, const td::Ref<ton::validator::BlockData>& data) {
  need(data.not_null() && data->block_id()==id,"MC handle/raw full ID mismatch");
  auto bytes=data->data(); need(!bytes.empty() && td::sha256_bits256(bytes.as_slice())==id.file_hash,
    "original BoC SHA256/file hash mismatch");
  auto root=data->root_cell(); need(root.not_null() && root->get_hash().as_bits256()==id.root_hash,
    "original BoC root hash mismatch");
  return root;
}
void mainnet_id(int32_t global_id) { need(global_id==-239,"wrong raw global ID/network"); }
std::optional<std::string> burned_value_flow(const td::Ref<vm::Cell>& cell) {
  need(cell.not_null(),"missing MC ValueFlow");
  const auto tag=vm::load_cell_slice(cell).prefetch_ulong(32);
  if (tag==0x3ebf98b7) {
    block::gen::ValueFlow::Record_value_flow_v2 flow;
    need(tlb::unpack_cell(cell,flow),"invalid MC ValueFlow v2");
    td::RefInt256 grams; td::Ref<vm::Cell> extra;
    need(block::unpack_CurrencyCollection(flow.burned,grams,extra) &&
      grams.not_null() && grams->is_valid() && td::sgn(grams)>=0,"invalid burned GRAM");
    return grams->to_dec_string();
  }
  if (tag==0xb8e48dfb) {
    block::gen::ValueFlow::Record_value_flow flow;
    need(tlb::unpack_cell(cell,flow),"invalid MC ValueFlow v1");
    return std::nullopt; // v1 has NO burned field: never zero.
  }
  throw std::runtime_error("unsupported MC ValueFlow constructor");
}
Record decode(ton::validator::ConstBlockHandle handle, td::Ref<ton::validator::BlockData> data) {
  need(bool(handle) && data.not_null(),"missing archived block");
  auto id=handle->id();
  need(id.is_valid_full() && id.is_masterchain() && id.id.shard==ton::shardIdAll,"wrong MC handle ID");
  auto root=verify_original_boc(id,data);
  block::gen::Block::Record raw; block::gen::BlockInfo::Record info;
  need(tlb::unpack_cell(root,raw) && tlb::unpack_cell(raw.info,info),"invalid raw MC header");
  mainnet_id(raw.global_id);
  need(info.seq_no==id.id.seqno && !info.not_master && info.shard.not_null(),
    "seqno or MC flag mismatch");
  block::ShardId shard(info.shard);
  need(shard.is_valid() && shard.workchain_id==ton::masterchainId && shard.shard_pfx==ton::shardIdAll,
    "wrong raw MC shard");
  auto head=ok(block::get_block_header_info(root,id),"raw MC full-ID predecessor");
  need(!head.after_split && head.prev.size()==1 && head.prev.front().is_valid_full() &&
    head.prev.front().is_masterchain() && head.prev.front().id.seqno+1==id.id.seqno &&
    head.mc_blkid==head.prev.front(),"wrong MC full-ID predecessor");
  need(raw.state_update.not_null() && vm::MerkleUpdate::validate(raw.state_update).is_ok(),"invalid Merkle update");
  bool special=false; auto update=vm::load_cell_slice_special(raw.state_update,special);
  td::Bits256 old_hash,new_hash;
  need(special && update.special_type()==vm::Cell::SpecialType::MerkleUpdate && update.size()==552 &&
    update.size_refs()==2 && update.fetch_ulong(8)==4 && update.fetch_bits_to(old_hash.bits(),256) &&
    update.fetch_bits_to(new_hash.bits(),256),"invalid Merkle old/new hashes");
  return {id,head.prev.front(),info.gen_utime,lower(old_hash.to_hex()),lower(new_hash.to_hex()),
          burned_value_flow(raw.value_flow)};
}
td::actor::Task<td::Unit> run(td::actor::ActorId<DbScanner> scanner, const Options& o, Checkpoints& cp) {
  try {
    auto start=std::chrono::steady_clock::now(); uint32_t chunks=0;
    std::optional<Record> previous;
    auto fetch = [&](uint32_t seq) -> td::actor::Task<Record> {
      auto handle=ok(co_await td::actor::ask(scanner,&DbScanner::get_mc_block_handle,seq).wrap(),"MC handle");
      auto data=ok(co_await td::actor::ask(scanner,&DbScanner::fetch_archived_block_boc,handle).wrap(),"archived BoC");
      co_return decode(handle,data);
    };
    while (cp.next<o.to && chunks<o.max_chunks) {
      if (chunks && std::chrono::steady_clock::now()-start >=
        std::chrono::seconds(o.max_seconds>30 ? o.max_seconds-30 : 0)) break;
      auto stop=static_cast<uint32_t>(std::min<uint64_t>(o.to,uint64_t(cp.next)+o.max_mc));
      // Fresh immutable predecessor evidence at each resume / chunk. Do not trust a receipt alone.
      if (!previous || previous->id.id.seqno+1!=cp.next)
        previous=ok(co_await fetch(cp.next-1).wrap(),"preceding MC");
      std::string body;
      for (uint32_t seq=cp.next; seq<stop; ++seq) {
        budgets(o);
        auto row=ok(co_await fetch(seq).wrap(),"raw MC block");
        need(row.previous==previous->id && row.old_state==previous->new_state &&
          row.utime>=previous->utime,"MC predecessor, Merkle continuity or time mismatch");
        need(row.utime>=1788220800u && row.utime<1790812800u,"raw MC time outside September");
        size_t day=(row.utime-1788220800u)/86400u;
        need(day<30 && seq>=o.pins.days[day].first.id.seqno &&
          seq<o.pins.days[day+1].first.id.seqno,"MC time vs pinned day range mismatch");
        if (seq==o.pins.days[day].first.id.seqno) {
          need(row.id==o.pins.days[day].first && previous->id==o.pins.days[day].prev &&
            row.utime>=o.pins.days[day].utc && previous->utime<o.pins.days[day].utc,
            "midnight full-ID or time pin mismatch");
        }
        for (size_t i=1;i<o.pins.days.size();++i) if (seq==o.pins.days[i].prev.id.seqno)
          need(row.id==o.pins.days[i].prev && row.utime<o.pins.days[i].utc,
               "preceding midnight full-ID pin mismatch");
        body += "{\"kind\":\"mc\",\"id\":"+json_id(row.id)+",\"prev\":"+json_id(row.previous)+
          ",\"gen_utime\":"+std::to_string(row.utime)+",\"day\":"+quote(o.pins.days[day].date)+
          ",\"state_old\":"+quote(row.old_state)+",\"state_new\":"+quote(row.new_state)+
          ",\"burned_nanoton\":"+(row.burned ? quote(*row.burned) : "null")+"}\n";
        need(body.size()+256<=o.max_output,"output cap exceeded; chunk uncommitted");
        previous=std::move(row);
      }
      budgets(o); cp.commit(stop,body); ++chunks;
      std::cerr << "immutable mc burn chunk through MC " << stop << " exclusive\n";
    }
    std::cerr << "checkpoint next MC " << cp.next << " (exclusive target " << o.to << ")\n";
    co_return td::Unit();
  } catch (const vm::VmError& e) { co_return e.as_status("raw MC burn decode: "); }
  catch (const std::exception& e) { co_return td::Status::Error(td::Slice(e.what())); }
}
void timeout(int) {
  constexpr char message[]="mc burn wall cap reached; in-progress chunk uncommitted\n";
  (void)write(STDERR_FILENO,message,sizeof(message)-1); _exit(1);
}
} // namespace burn

#ifndef MC_BURN_UNIT_TEST
int main(int argc,char** argv) {
  try {
    auto o=burn::parse(argc,argv);
    rlimit limit{}; burn::need(getrlimit(RLIMIT_NOFILE,&limit)==0,"getrlimit failed");
    limit.rlim_cur=std::min<rlim_t>(limit.rlim_cur,o.max_nofile);
    burn::need(limit.rlim_cur>=65536 && setrlimit(RLIMIT_NOFILE,&limit)==0,"NOFILE cap unavailable");
    burn::Checkpoints cp(o);
    if (cp.next==o.to) { std::cerr << "all requested MCs checkpointed; run offline audit\n"; return 0; }
    std::signal(SIGALRM,burn::timeout); alarm(o.max_seconds);
    SET_VERBOSITY_LEVEL(verbosity_WARNING);
    td::actor::Scheduler scheduler({2});
    td::actor::ActorOwn<DbScanner> scanner;
    auto status=std::make_shared<int>(1);
    auto watcher=td::create_shared_destructor([] { td::actor::SchedulerContext::get().stop(); });
    scheduler.run_in_context([&,watcher=std::move(watcher)]() mutable {
      scanner=td::actor::create_actor<DbScanner>("mc-burn-secondary",o.db.string(),dbs_secondary,
        std::make_optional(o.secondary.string()),static_cast<float>(o.max_seconds+60),false);
      auto done=td::PromiseCreator::lambda([watcher=std::move(watcher),status](td::Result<td::Unit> result) {
        if (result.is_error()) std::cerr << "mc burn unresolved: " << result.move_as_error().to_string() << '\n';
        else *status=0;
      });
      td::connect(std::move(done),burn::run(scanner.get(),o,cp).start());
    });
    scheduler.run(); alarm(0); return *status;
  } catch (const std::exception& e) { std::cerr << "mc burn: " << e.what() << '\n'; return 2; }
}
#endif
