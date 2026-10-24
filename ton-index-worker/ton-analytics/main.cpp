#include "Scheduler.h"
#include "td/utils/logging.h"
#include <csignal>
#include <iostream>
#include <unistd.h>

namespace {
void timeout(int) {
  constexpr char message[] = "ton-analytics: wall budget exceeded; current anchor not committed\n";
  (void)write(STDERR_FILENO, message, sizeof(message) - 1);
  _exit(1);
}
}
int main(int argc, char** argv) {
  using namespace tonstat::runner;
  try {
    auto options = parse_options({argv + 1, argv + argc});
#if !defined(TON_ANALYTICS_WITH_ACCOUNTS) || TON_ANALYTICS_WITH_ACCOUNTS != 1
    require(options.accounts_limit == 0, "Accounts sample adapter not built; see TON_ANALYTICS_WITH_ACCOUNTS compatibility notes");
#endif
    validate_paths(options);
    Progress progress(options.work, options.scope() + build_identity() + '\n', options.anchors, options.max_output_bytes, digest);
    require(std::signal(SIGALRM, timeout) != SIG_ERR, "cannot install wall budget");
    alarm(options.max_seconds);
    SET_VERBOSITY_LEVEL(verbosity_WARNING);
    td::actor::Scheduler scheduler({2});
    td::actor::ActorOwn<DbScanner> scanner;
    td::actor::ActorOwn<CatchUp> catchup;
    td::actor::ActorOwn<ParseManager> parser;
    auto code = std::make_shared<int>(1);
    auto watcher = td::create_shared_destructor([] { td::actor::SchedulerContext::get().stop(); });
    scheduler.run_in_context([&, watcher = std::move(watcher)]() mutable {
      // Periodic catchup stays beyond this bounded process's wall limit.
      scanner = td::actor::create_actor<DbScanner>("analytics-secondary", options.db.string(), dbs_secondary,
          std::make_optional(options.secondary.string()), static_cast<float>(options.max_seconds + 60), false);
      catchup = td::actor::create_actor<CatchUp>("analytics-catchup", scanner.get());
      parser = td::actor::create_actor<ParseManager>("analytics-parser");
      auto done = td::PromiseCreator::lambda([watcher = std::move(watcher), code](td::Result<td::Unit> result) {
        if (result.is_error()) std::cerr << "ton-analytics: " << result.move_as_error().to_string() << '\n';
        else *code = 0;
      });
      td::connect(std::move(done), run(scanner.get(), catchup.get(), parser.get(), options, progress).start());
    });
    scheduler.run(); alarm(0); return *code;
  } catch (const std::exception& e) {
    std::cerr << "ton-analytics: " << e.what() << '\n'
        << "Required: --network mainnet|testnet --zerostate-root HEX --zerostate-file HEX "
           "--db-root DIR --secondary-working-dir DIR --work-dir DIR "
           "(--from N --to M | --anchors-file FILE). See ton-analytics/README.md.\n";
    return 2;
  }
}
