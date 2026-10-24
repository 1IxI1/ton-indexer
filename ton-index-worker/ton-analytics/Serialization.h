#pragma once
#include "Options.h"
#include "../ton-analytics-core/AnchorEvidence.h"
#include "../ton-analytics-flow/Extractor.h"
#include <map>

namespace tonstat::runner {
std::string quote(const std::string& value);
std::string id_json(const ton::BlockIdExt& id);
std::string coordinate(const ton::BlockIdExt& id);
std::string digest(const std::string& value);
std::string build_identity();
ton::BlockIdExt native_id(const ton_analytics::flow::BlockId& id);
td::Bits256 bits(const std::string& hex);
struct ConfigSource {
  ton::BlockIdExt mc;
  td::Bits256 state_root, config8_hash;
  uint32_t version{};
};
class Rows {
 public:
  Rows(const Options& options, const std::string& scope, const tonstat::core::AnchorEvidence& evidence);
  void add(const std::string& dataset, const std::string& key, const std::string& status, const std::string& payload);
  void anchor(const tonstat::core::AnchorEvidence& evidence, bool graph_complete);
  void flow(const ton_analytics::flow::Batch& batch, const std::map<ton::BlockIdExt, ConfigSource>& configs);
  const std::string& text() const { return text_; }
 private:
  uint64_t limit_;
  std::string prefix_, text_;
};
} // namespace tonstat::runner
