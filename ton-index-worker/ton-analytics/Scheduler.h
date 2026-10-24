#pragma once
#include "Options.h"
#include "Progress.h"
#include "Serialization.h"
#include "DbScanner.h"
#include "td/actor/coro_utils.h"

namespace tonstat::runner {
// Adapts DbScanner's promise-first catchup method to ask's promise-last API.
class CatchUp final : public td::actor::Actor {
 public:
  explicit CatchUp(td::actor::ActorId<DbScanner> scanner) : scanner_(scanner) {}
  void once(td::Promise<td::Unit> promise) {
    td::actor::send_closure(scanner_, &DbScanner::request_catch_up, std::move(promise),
                            ton::validator::CatchUpMode::Force);
  }
 private:
  td::actor::ActorId<DbScanner> scanner_;
};
td::actor::Task<td::Unit> run(td::actor::ActorId<DbScanner> scanner, td::actor::ActorId<CatchUp> catchup,
                            td::actor::ActorId<ParseManager> parser, Options options, Progress& progress);
} // namespace tonstat::runner
