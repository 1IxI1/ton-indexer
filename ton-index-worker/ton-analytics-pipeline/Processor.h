#pragma once
#include "IndexAnalytics.h"
#include "Spool.h"
#include "../ton-analytics/Serialization.h"
#include <map>

namespace tonstat::pipeline {
struct Options {
  std::string network = "mainnet";
  std::uint32_t max_pending = 32;
  std::uint32_t config_history = 128; // hashes/version only, not retained states
  std::uint32_t max_blocks = 4096;
  std::uint32_t max_transactions = 100000;
  std::uint64_t max_batch_bytes = 64ULL * 1024 * 1024;
  std::vector<std::string> asset_wallets; // optional explicit address subset
};

// No scanner, parser, transport or database handles. All domain calls run against
// this retained parser result. The previous MC/reader is the only raw history.
class Processor {
 public:
  Processor(Options options, std::shared_ptr<Spool> spool);
  void process(std::uint32_t seqno, const ParsedBlockPtr& parsed, bool emit);
 private:
  Options options_;
  std::shared_ptr<Spool> spool_;
  core::NetworkPin pin_;
  std::map<ton::BlockIdExt, runner::ConfigSource> configs_;
  std::optional<schema::BlockDataState> previous_;
  std::shared_ptr<vm::CellDbReader> previous_reader_;
  std::shared_ptr<const core::AnchorEvidence> previous_evidence_;
};

class ProcessorActor final : public IndexAnalytics {
 public:
  ProcessorActor(Options options, std::shared_ptr<Spool> spool)
      : limit_(options.max_pending), processor_(std::move(options), std::move(spool)) {}
  void begin(std::uint32_t first_read_seqno) override;
  void process(std::uint32_t seqno, ParsedBlockPtr parsed, bool emit,
               td::Promise<td::Unit> promise) override;
 private:
  struct Pending { ParsedBlockPtr parsed; bool emit; td::Promise<td::Unit> promise; };
  void execute(std::uint32_t seqno, Pending pending);
  std::uint32_t next_{}, limit_;
  std::map<std::uint32_t, Pending> pending_;
  Processor processor_;
};
} // namespace tonstat::pipeline
