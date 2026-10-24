#ifdef NDEBUG
#undef NDEBUG
#endif
#include "Processor.h"
#include "IndexScheduler.h"
#include "validator/fabric.h"
#include "crypto/vm/boc.h"
#include "crypto/vm/db/DynamicBagOfCellsDb.h"
#include "td/utils/crypto.h"
#include "common/checksum.h"
#include <cassert>
#include <fstream>
#include <sstream>
#include <unistd.h>

class IndexSchedulerAnalyticsTest {
 public:
  static auto actions() { return &IndexScheduler::seqno_actions_processed; }
};

namespace {
using namespace tonstat;
namespace fs = std::filesystem;
struct Reader final : vm::CellDbReader {
  td::Result<td::Ref<vm::DataCell>> load_cell(td::Slice) override { return td::Status::Error("fixture missing historical code"); }
  td::Result<std::vector<td::Ref<vm::DataCell>>> load_bulk(td::Span<td::Slice>) override { return td::Status::Error("fixture missing historical code"); }
  td::Ref<vm::Cell> create_unloaded_cell(const td::Ref<vm::Cell>&, int) override { return {}; }
};
std::string read(const fs::path& p) { std::ifstream f(p); std::ostringstream out; out << f.rdbuf(); return out.str(); }

// Synthetic native cells and parsed transaction; deliberately no valid config,
// snapshot/baseline or archive claim. This exercises the ACTUAL processor and
// domain extractor -> checksum/fsync spool path with missing-context nulls.
ParsedBlockPtr fixture() {
  auto p = std::make_shared<ParsedBlock>(); p->cell_db_reader_ = std::make_shared<Reader>();
  const auto hash = td::sha256_bits256("synthetic-previous-block");
  auto before = vm::CellBuilder().store_long(1,32).finalize();
  auto after = vm::CellBuilder().store_long(2,32).finalize();
  auto update = vm::CellBuilder::create_merkle_update(before,after);
  auto prev = vm::CellBuilder().store_long(99,64).store_long(9,32).store_bits(hash.bits(),256).store_bits(hash.bits(),256).finalize();
  vm::CellBuilder info;
  info.store_long(0x9bc7a987,32).store_long(0,32).store_zeroes(8).store_zeroes(8)
      .store_long(10,32).store_long(0,32).store_zeroes(8).store_long(-1,32)
      .store_long(0,64).store_long(1789516800,32)
      .store_long(100,64).store_long(101,64).store_zeroes(128).store_ref(prev);
  auto empty = vm::CellBuilder().finalize();
  auto root = vm::CellBuilder().store_long(0x11ef55aa,32).store_long(-239,32)
      .store_ref(info.finalize()).store_ref(empty).store_ref(update).store_ref(empty).finalize();
  auto boc = vm::std_boc_serialize(root).move_as_ok();
  ton::BlockIdExt id{-1,ton::shardIdAll,10,root->get_hash().as_bits256(),td::sha256_bits256(boc.as_slice())};
  struct Block final : ton::validator::BlockData {
    ton::BlockIdExt id; td::Ref<vm::Cell> root; std::string bytes;
    Block(ton::BlockIdExt id,td::Ref<vm::Cell> root,std::string bytes) : id(id),root(std::move(root)),bytes(std::move(bytes)) {}
    td::BufferSlice data() const override { return td::BufferSlice(bytes); }
    ton::FileHash file_hash() const override { return id.file_hash; }
    ton::BlockIdExt block_id() const override { return id; }
    td::Ref<vm::Cell> root_cell() const override { return root; }
  };
  schema::BlockDataState raw;
  raw.handle = ton::validator::create_empty_block_handle(id);
  raw.block_data = td::Ref<Block>{true,id,root,boc.as_slice().str()}; raw.block_state = after;
  p->mc_block_.shard_blocks_.push_back(raw); p->mc_block_.shard_blocks_diff_.push_back(raw);
  schema::Block b{}; b.workchain=-1; b.shard=static_cast<int64_t>(ton::shardIdAll); b.seqno=10;
  b.gen_utime=1789516800; b.root_hash=td::base64_encode(id.root_hash.as_slice()); b.file_hash=td::base64_encode(id.file_hash.as_slice());
  schema::Transaction tx{}; tx.account = block::StdAddress(-1,hash); tx.hash=hash; tx.lt=100;
  tx.mc_seqno=10; tx.now=b.gen_utime; tx.orig_status=schema::active; tx.end_status=schema::nonexist;
  tx.account_state_hash_before=before->get_hash().as_bits256(); tx.account_state_hash_after=after->get_hash().as_bits256();
  tx.description=schema::TransactionDescr_ord{};
  schema::Message message{}; message.hash=hash;
  message.source=std::to_string(tx.account.workchain) + ":" + tx.account.addr.to_hex(); tx.out_msgs.push_back(message);
  b.transactions.push_back(tx); p->blocks_.push_back(b); return p;
}

struct Probe { ParsedBlockPtr expected; int callbacks{}, inserts{}; bool fail{}; };
class Hook final : public IndexAnalytics {
 public:
  explicit Hook(Probe* p) : p_(p) {}
  void begin(uint32_t) override {}
  void process(uint32_t,ParsedBlockPtr p,bool emit,td::Promise<td::Unit> promise) override {
    assert(p == p_->expected && p->cell_db_reader_ == p_->expected->cell_db_reader_ && emit);
    ++p_->callbacks;
    // Lease must survive an asynchronous actor turn.
    pending_ = std::move(p); promise_ = std::move(promise); alarm_timestamp() = td::Timestamp::in(0.001);
  }
  void alarm() override {
    assert(pending_ == p_->expected);
    if (p_->fail) promise_.set_error(td::Status::Error("injected durable analytics failure"));
    else promise_.set_value(td::Unit{});
    pending_.reset();
  }
 private: Probe* p_; ParsedBlockPtr pending_; td::Promise<td::Unit> promise_;
};
class Insert final : public InsertManagerInterface {
 public:
  explicit Insert(Probe* p) : p_(p) {}
  void insert(uint32_t,ParsedBlockPtr p,bool,td::Promise<QueueState> q,td::Promise<InsertResult> done) override {
    assert(p == p_->expected && p->cell_db_reader_ == p_->expected->cell_db_reader_);
    assert(++p_->inserts == 1); q.set_value(QueueState{}); done.set_value(InsertResult{});
    alarm_timestamp() = td::Timestamp::in(0.01);
  }
  void alarm() override { td::actor::SchedulerContext::get().stop(); }
  void get_insert_queue_state(td::Promise<QueueState> p) override { p.set_value(QueueState{}); }
  void get_existing_seqnos(td::Promise<std::vector<uint32_t>>,int32_t,int32_t) override { std::abort(); }
  void get_resume_seqno(td::Promise<ResumeState>,int32_t,int32_t) override { std::abort(); }
  void ensure_resume_state_initialized(td::Promise<bool>,int32_t) override { std::abort(); }
 private: Probe* p_;
};
void scheduler_case(const fs::path& root, bool enabled, bool fail) {
  fs::create_directories(root);
  Probe probe{fixture(),0,0,fail};
  td::actor::Scheduler scheduler({td::actor::Scheduler::NodeInfo{1,0}});
  auto config = enabled ? std::make_shared<IndexAnalyticsOptions>() : nullptr;
  td::actor::ActorOwn<IndexScheduler> index;
  td::actor::ActorOwn<Hook> hook; td::actor::ActorOwn<Insert> insert;
  scheduler.run_in_context([&] {
    insert = td::actor::create_actor<Insert>("insert-probe",&probe);
    hook = td::actor::create_actor<Hook>("hook-probe",&probe);
    if (config) config->processor = hook.get();
    // No DbScanner exists. Any extra fetch (including MC0) or main retry fails.
    index = td::actor::create_actor<IndexScheduler>("index-test",td::actor::ActorId<DbScanner>{},insert.get(),
        td::actor::ActorId<ParseManager>{},root.string(),0,0,false,2,QueueState{100,100,100,100},10,
        std::shared_ptr<td::Destructor>{},0,std::string{},config);
    td::actor::send_closure(index,IndexSchedulerAnalyticsTest::actions(),10,probe.expected);
  });
  while (scheduler.run(1)) {}
  assert(probe.inserts == 1 && probe.callbacks == (enabled ? 1 : 0));
  if (enabled) assert(config->failures.load() == (fail ? 1 : 0));
  scheduler.run_in_context([&] {
    index.reset(); hook.reset(); insert.reset();
    if (config) config->processor = {};
  });
}
} // namespace

int main(int argc, char** argv) {
  auto root = fs::canonical(fs::temp_directory_path())/("analytics-native-test-" + std::to_string(getpid()));
  fs::create_directories(root);
  auto p = fixture();
  auto spool = std::make_shared<pipeline::Spool>(root/"spool","synthetic-native-test-v1",pipeline::SpoolLimits{},runner::digest);
  pipeline::Processor processor({},spool);
  processor.process(10,p,true);
  const auto facts = read(root/"spool/10.committed/facts.ndjson");
  assert(facts.find("\"dataset\":\"wallet_qualifying_send\"") != std::string::npos);
  assert(facts.find("\"daily_activations\":null") != std::string::npos);
  assert(facts.find("\"dataset\":\"flow_pending\"") != std::string::npos);
  assert(facts.find("\"gross_fees_nanoton\":\"0\"") == std::string::npos);
  processor.process(10,p,true);
  assert(read(root/"spool/10.committed/facts.ndjson") == facts);
  scheduler_case(root/"disabled",false,false);
  scheduler_case(root/"enabled",true,false);
  scheduler_case(root/"failed",true,true);
  // Replay's insert adapter is structurally incapable of constructing CH and
  // deliberately ignores every pre-existing production seqno.
  AnalyticsReplayInsertManager replay;
  bool checked = false;
  replay.get_existing_seqnos(td::PromiseCreator::lambda([&](td::Result<std::vector<uint32_t>> r) {
    assert(r.is_ok() && r.ok().empty()); checked = true;
  }),1,100);
  assert(checked);
  if (argc == 2) fs::copy(root/"spool",fs::path(argv[1]),fs::copy_options::recursive);
  fs::remove_all(root);
}
