#include <algorithm>
#include <atomic>
#include <iomanip>
#include <iostream>
#include "DbScanner.h"
#include "TotalSupply.h"
#include "td/utils/OptionParser.h"
#include "td/utils/Timer.h"
#include "td/utils/filesystem.h"
#include "td/utils/misc.h"
#include "td/utils/port/path.h"
#include "td/utils/port/signals.h"
#include "vm/cp0.h"

namespace {

struct Options {
    std::string db, working_dir, mode = "incremental";
    td::uint32 from = 0, count = 256, threads = 8;
};

bool equal(const schema::TotalSupply& a, const schema::TotalSupply& b) {
    return a.mc_seqno == b.mc_seqno && a.gen_utime == b.gen_utime &&
        td::cmp(a.total, b.total) == 0 && td::cmp(a.accounts, b.accounts) == 0 &&
        td::cmp(a.dispatch_queue, b.dispatch_queue) == 0 &&
        td::cmp(a.unprocessed_messages, b.unprocessed_messages) == 0 &&
        td::cmp(a.unrecovered_validator_fees, b.unrecovered_validator_fees) == 0;
}

class BalanceBench : public td::actor::Actor {
    Options options_;
    int& exit_code_;
    std::shared_ptr<std::atomic_bool> finish_requested_;
    td::actor::ActorOwn<DbScanner> scanner_;
public:
    BalanceBench(Options options, int& exit_code, std::shared_ptr<std::atomic_bool> finish_requested)
        : options_(std::move(options)), exit_code_(exit_code), finish_requested_(std::move(finish_requested)) {}
    void start_up() override {
        scanner_ = td::actor::create_actor<DbScanner>("balance_bench_scanner", options_.db, dbs_secondary,
            std::optional<std::string>(options_.working_dir));
        auto promise = td::PromiseCreator::lambda([self = actor_id(this)](td::Result<td::Unit> result) {
            td::actor::send_closure(self, &BalanceBench::finished, std::move(result));
        });
        td::connect(std::move(promise), run());
    }
private:
    td::actor::Task<td::Unit> run() {
        gramstat::SupplyCache cache;
        auto loader = [scanner = scanner_.get()](ton::BlockIdExt id)
            -> td::actor::Task<td::Ref<ton::validator::ShardState>> {
            co_return co_await td::actor::ask(scanner, &DbScanner::fetch_state_by_id, id);
        };
        std::cout << "mc_seqno,fetch_s,prepare_s,compute_s,reference_s,reused,cold,with_prev,cached_tips,total,accounts,dispatch_queue,unprocessed_messages,validator_fees\n";
        std::vector<double> warm_times;
        td::Timer wall;
        for (td::uint32 i = 0; i < options_.count; ++i) {
            auto seqno = options_.from + i;
            td::Timer fetch;
            auto blocks = co_await td::actor::ask(scanner_, &DbScanner::fetch_seqno, seqno);
            auto fetch_seconds = fetch.elapsed();
            schema::TotalSupply snapshot;
            gramstat::SupplyStats stats;
            double reference_seconds = 0;
            if (options_.mode == "full") {
                td::Timer reference;
                snapshot = co_await gramstat::calculate_total_supply(blocks, loader);
                reference_seconds = reference.elapsed();
            } else {
                auto value = co_await gramstat::calculate_incremental_supply(blocks, loader, std::move(cache));
                snapshot = std::move(value.snapshot);
                cache = std::move(value.cache);
                stats = std::move(value.stats);
                if (options_.mode == "verify") {
                    td::Timer reference;
                    auto independent = co_await gramstat::calculate_total_supply(blocks, loader);
                    reference_seconds = reference.elapsed();
                    if (!equal(snapshot, independent)) {
                        co_return td::Status::Error("Supply component mismatch at MC " + std::to_string(seqno));
                    }
                }
            }
            auto calculation_seconds = options_.mode == "full" ? reference_seconds : stats.prepare_seconds + stats.compute_seconds;
            if (i) warm_times.push_back(calculation_seconds);
            std::cout << std::fixed << std::setprecision(6) << seqno << ',' << fetch_seconds << ','
                << stats.prepare_seconds << ',' << stats.compute_seconds << ',' << reference_seconds << ','
                << stats.reused << ',' << stats.cold << ',' << stats.with_prev << ',' << cache.states.size() << ','
                << snapshot.total->to_dec_string() << ',' << snapshot.accounts->to_dec_string() << ','
                << snapshot.dispatch_queue->to_dec_string() << ',' << snapshot.unprocessed_messages->to_dec_string() << ','
                << snapshot.unrecovered_validator_fees->to_dec_string() << '\n' << std::flush;
        }
        std::sort(warm_times.begin(), warm_times.end());
        auto percentile = [&](double p) { return warm_times.empty() ? 0.0 : warm_times[static_cast<std::size_t>((warm_times.size() - 1) * p)]; };
        LOG(INFO) << "Balance benchmark complete: mode=" << options_.mode << " count=" << options_.count
                  << " wall=" << wall.elapsed() << " warm_calc_p50=" << percentile(0.5)
                  << " warm_calc_p95=" << percentile(0.95) << " cached_tips=" << cache.states.size();
        co_return td::Unit{};
    }
    void finished(td::Result<td::Unit> result) {
        exit_code_ = result.is_ok() ? 0 : 1;
        if (result.is_error()) LOG(ERROR) << "Balance benchmark failed: " << result.error();
        scanner_.reset();
        finish_requested_->store(true);
        stop();
    }
};

}  // namespace

int main(int argc, char** argv) {
    td::set_default_failure_signal_handler().ensure();
    SET_VERBOSITY_LEVEL(verbosity_INFO);
    CHECK(vm::init_op_cp0());
    Options options;
    td::OptionParser parser;
    parser.set_description("Compare global balance calculations against a TON NodeDB; outputs CSV, writes no index tables");
    parser.add_option('h', "help", "Print help", [&] {
        td::StringBuilder text;
        text << parser;
        std::cout << text.as_cslice().str();
        std::exit(0);
    });
    parser.add_option('D', "db", "NodeDB directory", [&](td::Slice v) { options.db = v.str(); });
    parser.add_option('W', "working-dir", "Dedicated secondary RocksDB directory", [&](td::Slice v) { options.working_dir = v.str(); });
    parser.add_option('\0', "mode", "incremental (default), full, or verify", [&](td::Slice v) { options.mode = v.str(); });
    auto number = [&](td::Slice name, td::Slice help, td::uint32& target) {
        parser.add_checked_option('\0', name, help, [&target](td::Slice v) -> td::Status {
            TRY_RESULT(value, td::to_integer_safe<td::uint32>(v));
            if (!value) return td::Status::Error("Value must be positive");
            target = value;
            return td::Status::OK();
        });
    };
    number("from", "First MC seqno", options.from);
    number("count", "Number of consecutive MC blocks (default 256)", options.count);
    number("threads", "Scheduler CPU workers (default 8)", options.threads);
    auto status = parser.run(argc, argv);
    if (status.is_error() || options.db.empty() || options.working_dir.empty() || !options.from ||
        options.count - 1 > std::numeric_limits<td::uint32>::max() - options.from ||
        (options.mode != "incremental" && options.mode != "full" && options.mode != "verify")) {
        std::cerr << "Invalid arguments: specify --db, --working-dir, --from and a valid --mode\n";
        return 2;
    }
    td::mkpath(options.working_dir + "/").ensure();
    int exit_code = 1;
    auto finish_requested = std::make_shared<std::atomic_bool>(false);
    td::actor::ActorOwn<BalanceBench> runner;
    td::actor::Scheduler scheduler({td::actor::Scheduler::NodeInfo{options.threads, 1}});
    scheduler.run_in_context([&] { runner = td::actor::create_actor<BalanceBench>("balance_bench", options, exit_code, finish_requested); });
    while (!finish_requested->load() && scheduler.run(1)) {}
    scheduler.run_in_context([&] {
        runner.reset();
        td::actor::SchedulerContext::get().stop();
    });
    scheduler.run();
    return exit_code;
}
