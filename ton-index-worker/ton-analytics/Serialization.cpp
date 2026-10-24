#include "Serialization.h"
#include "../ton-analytics-gram/record.h"
#include "td/utils/crypto.h"
#include "td/utils/misc.h"

namespace tonstat::runner {
#ifndef TON_ANALYTICS_SOURCE_SHA256
#define TON_ANALYTICS_SOURCE_SHA256 "unrecorded-development-build"
#endif
#ifndef TON_ANALYTICS_TON_REVISION
#define TON_ANALYTICS_TON_REVISION "unrecorded-ton-revision"
#endif
std::string build_identity() {
  std::string result = std::string(TON_ANALYTICS_SOURCE_SHA256) + "/" + TON_ANALYTICS_TON_REVISION;
#if defined(TON_ANALYTICS_WITH_ACCOUNTS) && TON_ANALYTICS_WITH_ACCOUNTS == 1
  result += "/accounts-enabled";
#else
  result += "/accounts-disabled";
#endif
  return result;
}
std::string quote(const std::string& s) { return gram::json_string(s); }
std::string digest(const std::string& s) { return lower(td::hex_encode(td::sha256(s))); }
td::Bits256 bits(const std::string& hex) {
  require(hash_hex(hex), "invalid nonzero hash");
  td::Bits256 out;
  auto decoded = td::hex_decode(hex);
  require(decoded.is_ok(), "invalid hex");
  out.as_slice().copy_from(decoded.move_as_ok());
  return out;
}
std::string id_json(const ton::BlockIdExt& id) {
  return "{\"workchain\":" + std::to_string(id.id.workchain) + ",\"shard\":" + quote(gram::shard_hex(id.id.shard)) +
      ",\"seqno\":" + std::to_string(id.id.seqno) + ",\"root_hash\":" + quote(lower(id.root_hash.to_hex())) +
      ",\"file_hash\":" + quote(lower(id.file_hash.to_hex())) + "}";
}
std::string coordinate(const ton::BlockIdExt& id) {
  return std::to_string(id.id.workchain) + ":" + gram::shard_hex(id.id.shard) + ":" + std::to_string(id.id.seqno);
}
ton::BlockIdExt native_id(const ton_analytics::flow::BlockId& id) {
  return {id.workchain, id.shard, id.seqno, bits(id.root_hash), bits(id.file_hash)};
}
Rows::Rows(const Options& o, const std::string& scope, const tonstat::core::AnchorEvidence& e) : limit_(o.max_output_bytes) {
  require(e.mc_predecessors.size() == 1, "serializer requires verified raw MC predecessor");
  prefix_ = "{\"schema_version\":1,\"producer_version\":" + quote(kVersion) + ",\"scope_id\":" + quote(scope) +
      ",\"source_sha256\":" + quote(TON_ANALYTICS_SOURCE_SHA256) + ",\"ton_revision\":" + quote(TON_ANALYTICS_TON_REVISION) +
      ",\"network\":" + quote(e.network) + ",\"zerostate_root\":" + quote(o.zero_root) +
      ",\"zerostate_file\":" + quote(o.zero_file) + ",\"mc\":" + id_json(e.mc.id) +
      ",\"mc_predecessor\":" + id_json(e.mc_predecessors.front()) +
      ",\"mc_state_root\":" + quote(lower(e.mc.state_root.to_hex())) + ",\"mc_gen_utime\":" + std::to_string(e.mc.gen_utime) +
      ",\"requested_anchor_time_from\":" + std::to_string(o.anchor_time_from) + ",\"requested_anchor_time_to\":" + std::to_string(o.anchor_time_to) +
      ",\"source\":\"node_db_secondary\",\"mc_signatures_checked\":false,\"cryptographic_zerostate_link_checked\":false"
      ",\"publication_ready\":false,\"lifetime_complete\":false";
}
void Rows::add(const std::string& dataset, const std::string& key, const std::string& status, const std::string& body) {
  // Stable content key excludes run scope: replay through a new plan does not
  // invent another fact. Transport owns its own dedup/version/publication rules.
  auto row = prefix_ + ",\"dataset\":" + quote(dataset) + ",\"fact_key\":" + quote(key) +
      ",\"status\":" + quote(status) + ",\"payload\":" + body + "}\n";
  require(text_.size() <= limit_ && row.size() <= limit_ - text_.size(), "per-anchor output byte cap exceeded");
  text_ += row;
}
void Rows::anchor(const tonstat::core::AnchorEvidence& e, bool graph) {
  std::string body = "{\"verification_scope\":\"local_archive_hashes\",\"adjacent_mc_checked\":";
  body += e.continuity_status == core::Status::verified_local_archive ? "true" : "false";
  body += ",\"independent_tip_frontier_checked\":" + std::string(graph ? "true" : "false") +
      ",\"core_diff_exhaustiveness_checked\":" + (e.diff_exhaustiveness_checked ? "true" : "false") +
      ",\"calendar_day_complete\":false,\"checks\":[";
  bool first = true;
  for (const auto& c : e.checks) {
    if (!first) body += ','; first = false;
    body += "{\"code\":" + quote(c.code) + ",\"subject\":" + quote(c.subject) + ",\"observed\":" + quote(c.observed) + "}";
  }
  body += "],\"shard_tips\":["; first = true;
  for (const auto& tip : e.shard_tips) {
    if (!first) body += ','; first = false;
    body += "{\"id\":" + id_json(tip.id) + ",\"state_root\":" + quote(lower(tip.state_root.to_hex())) +
            ",\"gen_utime\":" + std::to_string(tip.gen_utime) + "}";
  }
  add("anchor", e.mc.id.to_str(), "verified_local_archive", body + "]}");
}
void Rows::flow(const ton_analytics::flow::Batch& b, const std::map<ton::BlockIdExt, ConfigSource>& configs) {
  for (const auto& f : b.blocks) {
    auto id = native_id(f.id); const auto& c = configs.at(id);
    std::string body = "{\"block\":" + id_json(id) + ",\"first_included_by\":" + id_json(native_id(f.first_included_by)) +
        ",\"gen_utime\":" + std::to_string(f.gen_utime) + ",\"mc_inclusion_utime\":" + std::to_string(f.mc_inclusion_utime) +
        ",\"applied_global_version\":" + std::to_string(f.applied_global_version) + ",\"execution_config_mc\":" + id_json(c.mc) +
        ",\"execution_config_state_root\":" + quote(lower(c.state_root.to_hex())) + ",\"config8_hash\":" + quote(lower(c.config8_hash.to_hex())) +
        ",\"tx_count\":" + std::to_string(f.tx_count) + ",\"tx_fee_augmentation_nanoton\":" + quote(f.tx_fee_augmentation_nanoton) +
        ",\"import_fee_augmentation_nanoton\":" + quote(f.import_fee_augmentation_nanoton) + ",\"gross_fees_nanoton\":" + quote(f.gross_fees_nanoton) +
        ",\"created_nanoton\":" + quote(f.created_nanoton) + ",\"burned_nanoton\":" + (f.burned_nanoton ? quote(*f.burned_nanoton) : "null") +
        ",\"burn_status\":" + quote(f.burn_status) + ",\"minted_grams_nanoton\":" + quote(f.minted_grams_nanoton) +
        ",\"zero_sink_sent_count\":" + std::to_string(f.zero_sink_sent_count) + ",\"zero_sink_sent_nanoton\":" + quote(f.zero_sink_sent_nanoton) +
        ",\"block_inventory_complete\":true,\"calendar_day_complete\":false}";
    add("block_flow", id.to_str(), "extracted", body);
  }
  for (const auto& f : b.zero_sink_sends) {
    auto id = native_id(f.source_block);
    add("zero_sink_send", id.to_str() + "/" + f.tx_hash + "/" + std::to_string(f.out_msg_index), "emitted_not_delivery",
        "{\"block\":" + id_json(id) + ",\"account_hex\":" + quote(lower(f.account_hex)) + ",\"tx_lt\":" + quote(std::to_string(f.tx_lt)) +
        ",\"tx_hash\":" + quote(lower(f.tx_hash)) + ",\"out_msg_index\":" + std::to_string(f.out_msg_index) +
        ",\"message_hash\":" + quote(lower(f.message_hash)) + ",\"tx_now\":" + std::to_string(f.tx_now) +
        ",\"value_nanoton\":" + quote(f.value_nanoton) + ",\"bounce\":" + (f.bounce ? "true" : "false") +
        ",\"bounced\":" + (f.bounced ? "true" : "false") + "}");
  }
}
} // namespace tonstat::runner
