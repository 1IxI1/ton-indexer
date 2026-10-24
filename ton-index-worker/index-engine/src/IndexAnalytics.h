#pragma once

#include "InsertManager.h"
#include <atomic>

// The optional stage borrows the SAME parser result, including its reader lease.
// Its promise acknowledges analytics durability, independently of legacy inserts.
class IndexAnalytics : public td::actor::Actor {
 public:
  virtual void begin(std::uint32_t first_read_seqno) = 0;
  virtual void process(std::uint32_t seqno, ParsedBlockPtr block, bool emit,
                       td::Promise<td::Unit> promise) = 0;
};

struct IndexAnalyticsOptions {
  td::actor::ActorId<IndexAnalytics> processor;
  bool only{false};
  std::atomic<std::uint64_t> failures{0};
};

// Replay still uses IndexScheduler's queue/ack contracts, but has no DB client,
// credentials, progress table, existing-mainnet seqno lookup, or insert side effects.
class AnalyticsReplayInsertManager final : public InsertManagerInterface {
 public:
  void insert(std::uint32_t, ParsedBlockPtr, bool, td::Promise<QueueState> queued,
              td::Promise<InsertResult> inserted) override {
    queued.set_value(QueueState{});
    inserted.set_value(InsertResult{});
  }
  void get_insert_queue_state(td::Promise<QueueState> promise) override {
    promise.set_value(QueueState{});
  }
  void get_existing_seqnos(td::Promise<std::vector<std::uint32_t>> promise,
                           std::int32_t = 0, std::int32_t = 0) override {
    promise.set_value(std::vector<std::uint32_t>{});
  }
  void ensure_resume_state_initialized(td::Promise<bool> promise, std::int32_t = 0) override {
    promise.set_error(td::Status::Error("analytics replay requires an explicit bounded range"));
  }
  void get_resume_seqno(td::Promise<ResumeState> promise, std::int32_t = 0, std::int32_t = 0) override {
    promise.set_error(td::Status::Error("analytics replay never reads legacy resume state"));
  }
};
