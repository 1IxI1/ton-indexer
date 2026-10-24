#pragma once
#include <cstdint>
#include <filesystem>
#include <functional>
#include <string>

namespace tonstat::pipeline {
struct SpoolLimits {
  std::uint64_t bytes = 1024ULL * 1024 * 1024;
  std::uint64_t batch_bytes = 64ULL * 1024 * 1024;
  std::uint32_t entries = 100000;
};

// One owner, bounded disk, no in-memory history. Compatible with pack_spool.py.
// Pending identity is fsynced BEFORE extraction; completion is atomic rename of
// facts + checksum receipt followed by parent fsync. A completed directory means
// local durability only, not store ingestion, metric readiness or publication.
class Spool {
 public:
  using Digest = std::function<std::string(const std::string&)>;
  Spool(std::filesystem::path root, std::string identity, SpoolLimits limits, Digest digest);
  ~Spool();
  Spool(const Spool&) = delete;
  bool completed(std::uint32_t seqno, const std::string& full_id) const;
  void prepare(std::uint32_t seqno, const std::string& full_id);
  void commit(std::uint32_t seqno, const std::string& full_id, const std::string& ndjson);
  void failed(std::uint32_t seqno, const std::string& full_id, const std::string& reason);
  const std::string& scope() const { return scope_; }
 private:
  std::filesystem::path root_;
  std::string scope_;
  SpoolLimits limits_;
  Digest digest_;
  std::uint64_t bytes_{};
  std::uint32_t entries_{};
  int lock_{-1};
  std::filesystem::path path(std::uint32_t seqno, const char* suffix) const;
  void overflow(std::uint32_t seqno);
};

// Outputs must be disjoint from NodeDB. Replay workdirs must be empty or carry
// our marker, preventing reuse of a production secondary/trace-assembler dir.
void validate_paths(const std::filesystem::path& db, const std::filesystem::path& work,
                    const std::filesystem::path& spool, bool replay);
} // namespace tonstat::pipeline
