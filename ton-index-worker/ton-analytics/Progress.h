#pragma once
#include "Options.h"
#include <functional>
#include <map>
#include <set>

namespace tonstat::runner {
using Digest = std::function<std::string(const std::string&)>;
struct Commit {
  uint32_t seqno{};
  std::string mc_id;
  // Coordinates detect duplicate/forked scopes even if hashes differ.
  std::vector<std::string> block_coordinates;
  std::string ndjson;
};
// One transaction = ALL selected extractors at one anchor. An atomic directory
// rename publishes facts+receipt together. Progress never consults main blocks.
class Progress {
 public:
  Progress(std::filesystem::path work, std::string scope, const std::vector<AnchorRequest>& plan,
           uint64_t byte_limit, Digest digest);
  ~Progress();
  Progress(const Progress&) = delete;
  Progress& operator=(const Progress&) = delete;
  bool completed(uint32_t seqno, const std::string& mc_id) const;
  void commit(const Commit& batch);
  // Retain independently successful snapshot facts on an event/Supply failure.
  // Never enters done_ or advances resume; retries replace only this failed attempt.
  void failed(uint32_t seqno, const std::string& ndjson);
  const std::string& scope_id() const { return scope_id_; }
  size_t completed_count() const { return done_.size(); }
 private:
  std::filesystem::path root_;
  std::string scope_id_;
  std::vector<uint32_t> plan_;
  uint64_t limit_;
  Digest digest_;
  std::map<uint32_t, std::string> done_;
  std::set<std::string> blocks_;
  int lock_ = -1;
};
} // namespace tonstat::runner
