#include "td/utils/port/signals.h"
#include "td/utils/OptionParser.h"
#include "td/utils/format.h"
#include "td/utils/logging.h"
#include "td/utils/check.h"
#include "td/utils/port/path.h"

#include "crypto/vm/cp0.h"

#include "InsertManagerClickhouse.h"
#include "DataParser.h"
#include "DbScanner.h"
#include "TraceAssembler.h"
#include "IndexScheduler.h"
#ifdef TON_INDEXER_ANALYTICS
#include "Processor.h"
#endif
#include <limits>


int main(int argc, char *argv[]) {
  SET_VERBOSITY_LEVEL(verbosity_INFO);
  td::set_default_failure_signal_handler().ensure();

  CHECK(vm::init_op_cp0());

  td::actor::ActorOwn<DbScanner> db_scanner_;
  td::actor::ActorOwn<ParseManager> parse_manager_;
  td::actor::ActorOwn<InsertManagerInterface> insert_manager_;
  td::actor::ActorId<InsertManagerClickhouse> legacy_insert_manager;
  td::actor::ActorOwn<IndexAnalytics> analytics_processor;
  std::shared_ptr<IndexAnalyticsOptions> analytics;
  td::actor::ActorOwn<IndexScheduler> index_scheduler_;

  // options
  td::uint32 threads = 7;
  td::uint32 io_workers = 1;
  td::int32 stats_timeout = 1;
  std::string db_root;
  std::string working_dir;
  td::uint32 last_known_seqno = 0;
  td::uint32 from_seqno = 0;
  td::uint32 to_seqno = 0;
  bool force_index = false;
  InsertManagerClickhouse::Credential credential;
  bool testnet = false;
  bool analytics_only = false, ch_explicit = false;
  std::string analytics_spool, analytics_network = "mainnet";
  std::vector<std::string> analytics_asset_wallets;
  std::uint64_t analytics_spool_bytes = 1024ULL * 1024 * 1024;
  std::uint32_t analytics_spool_entries = 100000, analytics_history = 128, prewarm = 50;

  std::uint32_t max_active_tasks = 7;
  std::uint32_t max_insert_actors = 12;
  
  std::int32_t max_queue_size{-1};
  std::int32_t max_batch_size{-1};
  QueueState max_queue{10000, 100000, 100000, 100000};
  QueueState batch_size{2000, 2000, 10000, 10000};

  td::OptionParser p;
  p.set_description("Parse TON DB and insert data into Clickhouse");
  p.add_option('\0', "help", "prints_help", [&]() {
    char b[10240];
    td::StringBuilder sb(td::MutableSlice{b, 10000});
    sb << p;
    std::cout << sb.as_cslice().c_str();
    std::exit(2);
  });
  p.add_option('D', "db", "Path to TON DB folder", [&](td::Slice fname) { 
    db_root = fname.str();
  });
  p.add_option('W', "working-dir", "Path to index working dir for secondary rocksdb logs", [&](td::Slice fname) { 
    working_dir = fname.str();
  });
  p.add_option('\0', "ch", "Clickhouse connection string",  [&](td::Slice value) {
    ch_explicit = true;
    credential.set_conn_str(value.str());
  });
  p.add_checked_option('f', "from", "Masterchain seqno to start indexing from", [&](td::Slice fname) { 
    int v;
    try {
      v = std::stoi(fname.str());
    } catch (...) {
      return td::Status::Error(ton::ErrorCode::error, "bad value for --from: not a number");
    }
    from_seqno = v;
    return td::Status::OK();
  });
  p.add_checked_option('\0', "to", "Masterchain seqno to end indexing", [&](td::Slice value) { 
    int v;
    try {
      v = std::stoi(value.str());
    } catch (...) {
      return td::Status::Error(ton::ErrorCode::error, "bad value for --to: not a number");
    }
    to_seqno = v;
    return td::Status::OK();
  });
  p.add_option('\0', "force", "Ignore existing seqnos and force reindex", [&]() {
    force_index = true;
    LOG(WARNING) << "Force reindexing enabled";
  });
  p.add_option('\0', "analytics-spool", "Opt in to analytics; absolute durable spool directory", [&](td::Slice s) { analytics_spool = s.str(); });
  p.add_option('\0', "analytics-only", "Bounded analytics replay in this pipeline; no legacy ClickHouse client", [&] { analytics_only = true; });
  p.add_option('\0', "analytics-network", "Pinned analytics network: mainnet (default) or testnet", [&](td::Slice s) { analytics_network = s.str(); });
  p.add_option('\0', "analytics-asset-wallet", "Optional historical asset wallet subset (repeatable, max 32)", [&](td::Slice s) { analytics_asset_wallets.push_back(s.str()); });
  auto positive = [](td::Slice s, std::uint64_t max) -> td::Result<std::uint64_t> {
    try {
      auto text = s.str(); size_t end = 0;
      if (text.empty() || text[0] == '-') return td::Status::Error("expected positive integer");
      auto n = std::stoull(text,&end);
      if (!n || n > max || end != text.size()) return td::Status::Error("integer out of range");
      return n;
    } catch (...) { return td::Status::Error("expected positive integer"); }
  };
  p.add_checked_option('\0', "analytics-spool-bytes", "Total spool byte budget (default 1 GiB)", [&](td::Slice s) {
    auto n = positive(s,1ULL << 50); if (n.is_error()) return n.move_as_error(); analytics_spool_bytes = n.move_as_ok(); return td::Status::OK();
  });
  p.add_checked_option('\0', "analytics-spool-entries", "Total spool anchor budget (default 100000)", [&](td::Slice s) {
    auto n = positive(s,1000000); if (n.is_error()) return n.move_as_error(); analytics_spool_entries = n.move_as_ok(); return td::Status::OK();
  });
  p.add_checked_option('\0', "analytics-config-history", "Retained historical config metadata count (default 128)", [&](td::Slice s) {
    auto n = positive(s,4096); if (n.is_error()) return n.move_as_error(); analytics_history = n.move_as_ok(); return td::Status::OK();
  });
  p.add_checked_option('\0', "prewarm", "Read preceding blocks for traces/configs; never emit outside replay range (default 50)", [&](td::Slice s) {
    if (s.str() == "0") { prewarm = 0; return td::Status::OK(); }
    auto n = positive(s,100000); if (n.is_error()) return n.move_as_error(); prewarm = n.move_as_ok(); return td::Status::OK();
  });
  p.add_checked_option('\0', "max-active-tasks", "Max active reading tasks", [&](td::Slice fname) {
    int v;
    try {
      v = std::stoi(fname.str());
    } catch (...) {
      return td::Status::Error(ton::ErrorCode::error, "bad value for --max-active-tasks: not a number");
    }
    max_active_tasks = v;
    return td::Status::OK();
  });

  // queue settings
  p.add_checked_option('\0', "max-queue-blocks", "Max blocks in insert queue", [&](td::Slice fname) { 
    int v;
    try {
      v = std::stoi(fname.str());
    } catch (...) {
      return td::Status::Error(ton::ErrorCode::error, "bad value for --max-queue-blocks: not a number");
    }
    max_queue.mc_blocks_ = v;
    max_queue.blocks_ = v;
    return td::Status::OK();
  });
  p.add_checked_option('\0', "max-queue-txs", "Max transactions in insert queue", [&](td::Slice fname) { 
    int v;
    try {
      v = std::stoi(fname.str());
    } catch (...) {
      return td::Status::Error(ton::ErrorCode::error, "bad value for --max-queue-txs: not a number");
    }
    max_queue.txs_ = v;
    return td::Status::OK();
  });
  p.add_checked_option('\0', "max-queue-msgs", "Max messages in insert queue", [&](td::Slice fname) { 
    int v;
    try {
      v = std::stoi(fname.str());
    } catch (...) {
      return td::Status::Error(ton::ErrorCode::error, "bad value for --max-queue-msgs: not a number");
    }
    max_queue.msgs_ = v;
    return td::Status::OK();
  });

  // insert manager settings
  p.add_checked_option('\0', "max-insert-actors", "Number of parallel insert actors (default: 3)", [&](td::Slice fname) { 
    int v;
    try {
      v = std::stoi(fname.str());
    } catch (...) {
      return td::Status::Error(ton::ErrorCode::error, "bad value for --max-insert-actors: not a number");
    }
    max_insert_actors = v;
    return td::Status::OK();
  });
  p.add_checked_option('\0', "max-batch-blocks", "Max blocks in batch", [&](td::Slice fname) { 
    int v;
    try {
      v = std::stoi(fname.str());
    } catch (...) {
      return td::Status::Error(ton::ErrorCode::error, "bad value for --max-batch-blocks: not a number");
    }
    batch_size.mc_blocks_ = v;
    batch_size.blocks_ = v;
    return td::Status::OK();
  });
  p.add_checked_option('\0', "max-batch-txs", "Max transactions in batch", [&](td::Slice fname) { 
    int v;
    try {
      v = std::stoi(fname.str());
    } catch (...) {
      return td::Status::Error(ton::ErrorCode::error, "bad value for --max-batch-txs: not a number");
    }
    batch_size.txs_ = v;
    return td::Status::OK();
  });
  p.add_checked_option('\0', "max-batch-msgs", "Max messages in batch", [&](td::Slice fname) { 
    int v;
    try {
      v = std::stoi(fname.str());
    } catch (...) {
      return td::Status::Error(ton::ErrorCode::error, "bad value for --max-batch-msgs: not a number");
    }
    batch_size.msgs_ = v;
    return td::Status::OK();
  });

  p.add_checked_option('\0', "max-queue-size", "Max size of insert queue", [&](td::Slice fname) {
    int v;
    try {
      v = std::stoi(fname.str());
    } catch (...) {
      return td::Status::Error(ton::ErrorCode::error, "bad value for --max-queue-size: not a number");
    }
    max_queue_size = v;
    return td::Status::OK();
  });
  p.add_checked_option('\0', "max-batch-size", "Max size of batch", [&](td::Slice fname) {
    int v;
    try {
      v = std::stoi(fname.str());
    } catch (...) {
      return td::Status::Error(ton::ErrorCode::error, "bad value for --max-queue-size: not a number");
    }
    max_batch_size = v;
    return td::Status::OK();
  });

  // scheduler settings
  p.add_checked_option('t', "threads", "Scheduler threads (default: 7)", [&](td::Slice fname) { 
    int v;
    try {
      v = std::stoi(fname.str());
    } catch (...) {
      return td::Status::Error(ton::ErrorCode::error, "bad value for --threads: not a number");
    }
    threads = v;
    return td::Status::OK();
  });
  p.add_checked_option('\0', "io-workers", "Scheduler IO workers (default: 1)", [&](td::Slice fname) {
    int v;
    try {
      v = std::stoi(fname.str());
    } catch (...) {
      return td::Status::Error(ton::ErrorCode::error, "bad value for --io-workers: not a number");
    }
    io_workers = v;
    return td::Status::OK();
  });
  p.add_checked_option('\0', "stats-freq", "Pause between printing stats in seconds", [&](td::Slice fname) { 
    int v;
    try {
      v = std::stoi(fname.str());
    } catch (...) {
      return td::Status::Error(ton::ErrorCode::error, "bad value for --stats-freq: not a number");
    }
    stats_timeout = v;
    return td::Status::OK();
  });
  auto S = p.run(argc, argv);
  if (S.is_error()) {
    LOG(ERROR) << "failed to parse options: " << S.move_as_error();
    std::_Exit(2);
  }
  if (working_dir.size() == 0) {
    LOG(ERROR) << "Please specify working directory with -W or --working-dir";
    std::_Exit(2);
  }
  const bool bounded_archive_range = from_seqno > 0 && to_seqno > 0;
  if (analytics_only && (analytics_spool.empty() || !bounded_archive_range || from_seqno > to_seqno ||
                        to_seqno > INT32_MAX || ch_explicit || force_index ||
                        static_cast<std::uint64_t>(to_seqno) - from_seqno + 1 > analytics_spool_entries)) {
    LOG(ERROR) << "--analytics-only requires --analytics-spool and a positive bounded range fitting --analytics-spool-entries; conflicts with --ch/--force";
    return 2;
  }
  if ((!analytics_asset_wallets.empty() || analytics_network != "mainnet") && analytics_spool.empty()) {
    LOG(ERROR) << "Analytics options require --analytics-spool"; return 2;
  }
#ifndef TON_INDEXER_ANALYTICS
  if (!analytics_spool.empty()) { LOG(ERROR) << "Rebuild with -DTON_INDEXER_ANALYTICS=ON to enable analytics"; return 2; }
#else
  std::shared_ptr<tonstat::pipeline::Spool> spool;
  tonstat::pipeline::Options analytics_options;
  if (!analytics_spool.empty()) {
    try {
      if (!max_active_tasks || max_active_tasks > 1024 || analytics_asset_wallets.size() > 32)
        throw std::runtime_error("analytics needs 1..1024 active tasks and at most 32 asset wallets");
      analytics_options.network = analytics_network; analytics_options.max_pending = max_active_tasks;
      analytics_options.config_history = analytics_history; analytics_options.asset_wallets = analytics_asset_wallets;
      if (analytics_network != "mainnet" && analytics_network != "testnet") throw std::runtime_error("invalid analytics network");
      for (const auto& text : analytics_asset_wallets) {
        block::StdAddress a; if (!a.parse_addr(text)) throw std::runtime_error("invalid analytics asset wallet address");
      }
      tonstat::pipeline::validate_paths(db_root,working_dir,analytics_spool,analytics_only);
      std::string identity = "IndexScheduler-analytics-v1\n" + tonstat::runner::build_identity() + "\n" + analytics_network + "\n";
      for (const auto& a : analytics_asset_wallets) identity += a + "\n";
      spool = std::make_shared<tonstat::pipeline::Spool>(analytics_spool,identity,
          tonstat::pipeline::SpoolLimits{analytics_spool_bytes,analytics_options.max_batch_bytes,analytics_spool_entries},
          tonstat::runner::digest);
      analytics = std::make_shared<IndexAnalyticsOptions>(); analytics->only = analytics_only;
    } catch (const std::exception& e) { LOG(ERROR) << "Analytics startup: " << e.what(); return 2; }
  }
#endif
  const float db_catch_up_interval = bounded_archive_range ? 60.0f : 1.0f;
  td::mkpath(working_dir + "/").ensure();

  if (max_queue_size > 0) {
    max_queue.mc_blocks_ = max_queue_size;
    max_queue.blocks_ = max_queue_size;
    max_queue.txs_ = max_queue_size;
    max_queue.msgs_ = max_queue_size;
    max_queue.traces_ = max_queue_size;
  }

  if (max_batch_size > 0) {
    batch_size.mc_blocks_ = max_batch_size;
    batch_size.blocks_ = max_batch_size;
    batch_size.txs_ = max_batch_size;
    batch_size.msgs_ = max_batch_size;
    batch_size.traces_ = max_batch_size;
  }

  NftItemDetectorR::is_testnet = testnet;

  auto watcher = td::create_shared_destructor([] {
    td::actor::SchedulerContext::get().stop();
  });

  td::actor::Scheduler scheduler({td::actor::Scheduler::NodeInfo{threads, io_workers}});
  scheduler.run_in_context([&] {
    if (analytics_only) {
      insert_manager_ = td::actor::create_actor<AnalyticsReplayInsertManager>("analytics_replay_ack");
    } else {
      auto legacy = td::actor::create_actor<InsertManagerClickhouse>("insertmanager", credential);
      legacy_insert_manager = legacy.get(); insert_manager_ = std::move(legacy);
    }
#ifdef TON_INDEXER_ANALYTICS
    if (analytics) {
      analytics_processor = td::actor::create_actor<tonstat::pipeline::ProcessorActor>("analytics",analytics_options,spool);
      analytics->processor = analytics_processor.get();
    }
#endif
  });
  scheduler.run_in_context([&] { parse_manager_ = td::actor::create_actor<ParseManager>("parsemanager"); });
  scheduler.run_in_context([&] {
    db_scanner_ = td::actor::create_actor<DbScanner>("scanner", db_root, dbs_secondary,
                                                     working_dir + "/secondary_logs", db_catch_up_interval,
                                                     !bounded_archive_range);
  });

  scheduler.run_in_context([&, watcher = std::move(watcher)] { index_scheduler_ = td::actor::create_actor<IndexScheduler>("indexscheduler", db_scanner_.get(), 
    insert_manager_.get(), parse_manager_.get(), working_dir, from_seqno, to_seqno, force_index, max_active_tasks, max_queue, stats_timeout, watcher,
    prewarm, std::string{}, analytics);
  });
  scheduler.run_in_context([&] { 
    if (!analytics_only) {
      td::actor::send_closure(legacy_insert_manager, &InsertManagerClickhouse::set_parallel_inserts_actors, max_insert_actors);
      td::actor::send_closure(legacy_insert_manager, &InsertManagerClickhouse::set_insert_batch_size, batch_size);
      td::actor::send_closure(legacy_insert_manager, &InsertManagerClickhouse::print_info);
    }
  });
  scheduler.run_in_context([&] { td::actor::send_closure(index_scheduler_, &IndexScheduler::run); });
  
  while(scheduler.run(1)) {
    // do something
  }
  scheduler.run_in_context([&] {
    index_scheduler_.reset(); analytics_processor.reset();
    insert_manager_.reset(); parse_manager_.reset(); db_scanner_.reset();
    legacy_insert_manager = {};
    if (analytics) analytics->processor = {};
  });
  LOG(INFO) << "Done!";
  return analytics_only && analytics && analytics->failures.load() ? 3 : 0;
}
