#include "AssetFacts.h"

#include <algorithm>
#include <cstddef>
#include <stdexcept>
#include <string>
#include <vector>

namespace assets_analytics {
namespace {

constexpr std::size_t kMaxJsonBytes = 256 * 1024;

void room(const std::string& out, std::size_t bytes) {
  if (bytes > kMaxJsonBytes || out.size() > kMaxJsonBytes - bytes) {
    throw std::length_error("assets batch JSON exceeds 256 KiB");
  }
}

// Avoid constructing an enormous canonical manifest or sorting an unbounded
// vector before serialization. Every listed string appears at least once in
// the output; this is a conservative lower bound, not a replacement for room().
void charge(std::size_t& remaining, const std::string& s) {
  if (s.size() > remaining) throw std::length_error("assets batch input exceeds 256 KiB");
  remaining -= s.size();
}

void check_input_budget(const BatchMeta& m, const std::vector<Observation>& observations) {
  std::size_t remaining = kMaxJsonBytes;
  charge(remaining, m.network); charge(remaining, m.zerostate);
  charge(remaining, m.zerostate_file_hash); charge(remaining, m.calc_version);
  charge(remaining, m.mc_full_id); charge(remaining, m.mc_state_root_hash);
  if (observations.size() > kMaxJsonBytes / 128) {
    throw std::length_error("assets batch has too many observations");
  }
  const auto optional = [&](const std::optional<std::string>& value) {
    if (value) charge(remaining, *value);
  };
  const auto tips = [&](const std::vector<TipSource>& entries) {
    if (entries.size() > kMaxJsonBytes / 32) throw std::length_error("assets batch has too many tips");
    for (const auto& t : entries) {
      charge(remaining, t.block_id); charge(remaining, t.state_root_hash);
    }
  };
  const auto account = [&](const AccountEvidence& a) {
    charge(remaining, a.address); charge(remaining, a.state_hash); charge(remaining, a.code_hash);
    charge(remaining, a.data_hash); charge(remaining, a.account_status);
    charge(remaining, a.ton_balance_nanoton); charge(remaining, a.extra_currencies_hash);
  };
  for (const auto& o : observations) {
    charge(remaining, o.wallet.address); charge(remaining, o.reason);
    account(o.wallet); account(o.master);
    optional(o.raw_signed_balance); optional(o.owner); optional(o.master_address);
    optional(o.getter_wallet_code_hash); optional(o.master_returned_wallet);
    const auto& p = o.source;
    charge(remaining, p.network); charge(remaining, p.zerostate);
    charge(remaining, p.mc_block_id); charge(remaining, p.mc_state_root_hash);
    tips(p.current_shard_tips);
    charge(remaining, p.tip_manifest_sha256); charge(remaining, p.tip_block_id);
    charge(remaining, p.tip_state_root_hash); charge(remaining, p.master_tip_block_id);
    charge(remaining, p.master_tip_state_root_hash); charge(remaining, p.config_hash);
    charge(remaining, p.vm_context_limits);
    if (o.context_audit) {
      const auto& a = *o.context_audit;
      charge(remaining, a.report_id); charge(remaining, a.report_sha256);
      charge(remaining, a.allowlist_policy_version); charge(remaining, a.c7_dependency_assessment);
      charge(remaining, a.wallet_address); charge(remaining, a.wallet_state_hash);
      charge(remaining, a.wallet_code_hash); charge(remaining, a.master_address);
      charge(remaining, a.master_state_hash); charge(remaining, a.master_code_hash);
      charge(remaining, a.mc_block_id); charge(remaining, a.mc_state_root_hash);
      charge(remaining, a.tip_manifest_sha256); tips(a.current_shard_tips);
      charge(remaining, a.config_hash); charge(remaining, a.wallet_method);
      charge(remaining, a.master_method); charge(remaining, a.audited_vm_context_limits);
    }
  }
}

bool valid_version(const std::string& version) {
  if (version.empty()) return false;
  const auto alnum = [](char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
  };
  if (!alnum(version.front())) return false;
  return std::all_of(version.begin(), version.end(), [&](char c) {
    return alnum(c) || c == '.' || c == '_' || c == '-' || c == '+';
  });
}

// Byte-stable, ASCII-only JSON. Escaping every non-ASCII byte as \u00XX also
// produces valid JSON for malformed UTF-8 received from an untrusted source.
void quoted(std::string& out, const std::string& s) {
  constexpr char hex[] = "0123456789abcdef";
  room(out, 1);
  out += '"';
  for (unsigned char c : s) {
    switch (c) {
      case '"': room(out, 2); out += "\\\""; break;
      case '\\': room(out, 2); out += "\\\\"; break;
      case '\b': room(out, 2); out += "\\b"; break;
      case '\f': room(out, 2); out += "\\f"; break;
      case '\n': room(out, 2); out += "\\n"; break;
      case '\r': room(out, 2); out += "\\r"; break;
      case '\t': room(out, 2); out += "\\t"; break;
      default:
        if (c < 0x20 || c >= 0x7f) {
          room(out, 6);
          out += "\\u00";
          out += hex[c >> 4];
          out += hex[c & 15];
        } else {
          room(out, 1);
          out += static_cast<char>(c);
        }
    }
  }
  room(out, 1);
  out += '"';
}

void field(std::string& out, const char* key, const std::string& value) {
  quoted(out, key);
  out += ':';
  quoted(out, value);
}

void bool_field(std::string& out, const char* key, bool value) {
  quoted(out, key);
  out += value ? ":true" : ":false";
}

void optional_field(std::string& out, const char* key, const std::optional<std::string>& value) {
  quoted(out, key);
  out += ':';
  if (value) quoted(out, *value);
  else out += "null";
}

const char* name(Status s) {
  switch (s) {
    case Status::found: return "found";
    case Status::not_present: return "not_present";
    case Status::unknown: return "unknown";
    case Status::error: return "error";
  }
  return "unknown";
}

const char* name(AccountLookup s) {
  switch (s) {
    case AccountLookup::found: return "found";
    case AccountLookup::not_present: return "not_present";
    case AccountLookup::unknown: return "unknown";
    case AccountLookup::error: return "error";
  }
  return "unknown";
}

const char* name(Binding b) {
  switch (b) {
    case Binding::untested: return "untested";
    case Binding::matched: return "matched";
    case Binding::unmatched: return "unmatched";
  }
  return "untested";
}

void account(std::string& out, const AccountEvidence& a) {
  out += '{';
  field(out, "lookup", name(a.lookup)); out += ',';
  field(out, "address", a.address); out += ',';
  field(out, "account_status", a.account_status); out += ',';
  field(out, "state_hash", a.state_hash); out += ',';
  field(out, "code_hash", a.code_hash); out += ',';
  field(out, "data_hash", a.data_hash); out += ',';
  // Native TON balance is not jetton balance; keep both as decimal strings.
  field(out, "ton_balance_nanoton", a.ton_balance_nanoton); out += ',';
  field(out, "extra_currencies_hash", a.extra_currencies_hash);
  out += '}';
}

void tips(std::string& out, const std::vector<TipSource>& input) {
  auto sorted = input;
  std::sort(sorted.begin(), sorted.end(), [](const TipSource& a, const TipSource& b) {
    return a.block_id < b.block_id || (a.block_id == b.block_id && a.state_root_hash < b.state_root_hash);
  });
  out += '[';
  for (const auto& tip : sorted) {
    if (&tip != &sorted.front()) out += ',';
    out += '{';
    field(out, "full_block_id", tip.block_id); out += ',';
    field(out, "state_root_hash", tip.state_root_hash);
    out += '}';
  }
  out += ']';
}

bool source_consistent(const BatchMeta& m, const Observation& o,
                       const std::string& reference_manifest, const std::string& reference_digest) {
  const auto& p = o.source;
  if (p.network != m.network || p.zerostate != m.zerostate || p.mc_block_id != m.mc_full_id ||
      p.mc_state_root_hash != m.mc_state_root_hash || p.historical_now != m.mc_gen_utime ||
      !valid_report_digest(p.tip_manifest_sha256) || p.tip_manifest_sha256 != reference_digest ||
      canonical_tip_manifest(p.current_shard_tips) != reference_manifest || p.current_shard_tips.empty()) return false;
  auto sorted = p.current_shard_tips;
  std::sort(sorted.begin(), sorted.end(), [](const TipSource& a, const TipSource& b) {
    return a.block_id < b.block_id || (a.block_id == b.block_id && a.state_root_hash < b.state_root_hash);
  });
  for (size_t i = 0; i < sorted.size(); ++i) {
    if (sorted[i].block_id.empty() || sorted[i].state_root_hash.empty() ||
        (i && sorted[i].block_id == sorted[i - 1].block_id)) return false;
  }
  return true;  // Digest is caller-provided; authenticity/completeness is NOT established here.
}

void source(std::string& out, const Provenance& p) {
  out += '{';
  field(out, "network", p.network); out += ',';
  field(out, "zerostate", p.zerostate); out += ',';
  field(out, "mc_full_id", p.mc_block_id); out += ',';
  field(out, "mc_state_root_hash", p.mc_state_root_hash); out += ',';
  out += "\"mc_gen_utime\":" + std::to_string(p.historical_now) + ',';
  out += "\"current_shard_tips\":";
  tips(out, p.current_shard_tips); out += ',';
  field(out, "tip_manifest_sha256", p.tip_manifest_sha256); out += ',';
  field(out, "wallet_tip_full_id", p.tip_block_id); out += ',';
  field(out, "wallet_tip_state_root_hash", p.tip_state_root_hash); out += ',';
  field(out, "master_tip_full_id", p.master_tip_block_id); out += ',';
  field(out, "master_tip_state_root_hash", p.master_tip_state_root_hash); out += ',';
  field(out, "config_hash", p.config_hash); out += ',';
  field(out, "vm_context_limits", p.vm_context_limits); out += ',';
  bool_field(out, "caller_attests_state_updates", p.caller_attests_state_updates); out += ',';
  bool_field(out, "caller_attests_manifest_complete", p.caller_attests_manifest_complete); out += ',';
  bool_field(out, "caller_attests_config_from_mc", p.caller_attests_config_from_mc);
  out += '}';
}

void audit(std::string& out, const std::optional<GetterContextAudit>& a) {
  if (!a) { out += "null"; return; }
  out += '{';
  field(out, "report_id", a->report_id); out += ',';
  field(out, "report_sha256", a->report_sha256); out += ',';
  field(out, "allowlist_policy_version", a->allowlist_policy_version); out += ',';
  field(out, "c7_dependency_assessment", a->c7_dependency_assessment); out += ',';
  field(out, "wallet_address", a->wallet_address); out += ',';
  field(out, "wallet_state_hash", a->wallet_state_hash); out += ',';
  field(out, "wallet_code_hash", a->wallet_code_hash); out += ',';
  field(out, "master_address", a->master_address); out += ',';
  field(out, "master_state_hash", a->master_state_hash); out += ',';
  field(out, "master_code_hash", a->master_code_hash); out += ',';
  field(out, "mc_full_id", a->mc_block_id); out += ',';
  field(out, "mc_state_root_hash", a->mc_state_root_hash); out += ',';
  field(out, "tip_manifest_sha256", a->tip_manifest_sha256); out += ',';
  out += "\"current_shard_tips\":";
  tips(out, a->current_shard_tips); out += ',';
  field(out, "config_hash", a->config_hash); out += ',';
  out += "\"historical_now\":" + std::to_string(a->historical_now) + ',';
  field(out, "wallet_method", a->wallet_method); out += ',';
  field(out, "master_method", a->master_method); out += ',';
  field(out, "audited_vm_context_limits", a->audited_vm_context_limits);
  out += '}';
}

}  // namespace

std::string render_batch_json(const BatchMeta& meta, const std::vector<Observation>& observations) {
  if (meta.network.empty() || meta.zerostate.empty() || meta.zerostate_file_hash.empty() ||
      !valid_version(meta.calc_version) ||
      meta.mc_full_id.empty() || meta.mc_state_root_hash.empty() || !meta.mc_gen_utime) {
    throw std::invalid_argument("assets batch requires network, zerostate root+file, calc_version, full MC ID, state root and time");
  }
  check_input_budget(meta, observations);
  std::vector<const Observation*> ordered;
  ordered.reserve(observations.size());
  for (const auto& o : observations) {
    if (o.wallet.address.empty()) throw std::invalid_argument("assets batch: wallet address missing");
    ordered.push_back(&o);
  }
  std::sort(ordered.begin(), ordered.end(), [](const Observation* a, const Observation* b) {
    return a->wallet.address < b->wallet.address;
  });
  for (size_t i = 1; i < ordered.size(); ++i) {
    if (ordered[i - 1]->wallet.address == ordered[i]->wallet.address) {
      throw std::invalid_argument("assets batch: duplicate wallet address");
    }
  }

  const std::string manifest = ordered.empty() ? "" : canonical_tip_manifest(ordered[0]->source.current_shard_tips);
  const std::string digest = ordered.empty() ? "" : ordered[0]->source.tip_manifest_sha256;
  bool ready = !ordered.empty();
  std::string out = "{";
  field(out, "dataset", "assets"); out += ',';
  field(out, "metric", "jetton_wallet_address_observation"); out += ',';
  field(out, "scope", "address_subset_at_anchor"); out += ',';
  field(out, "network", meta.network); out += ',';
  field(out, "zerostate", meta.zerostate); out += ',';
  field(out, "zerostate_file_hash", meta.zerostate_file_hash); out += ',';
  field(out, "calc_version", meta.calc_version); out += ',';
  field(out, "mc_full_id", meta.mc_full_id); out += ',';
  field(out, "mc_state_root_hash", meta.mc_state_root_hash); out += ',';
  out += "\"mc_gen_utime\":" + std::to_string(meta.mc_gen_utime) + ',';
  out += "\"observations\":[";
  for (size_t i = 0; i < ordered.size(); ++i) {
    if (i) out += ',';
    const auto& o = *ordered[i];
    const bool consistent = source_consistent(meta, o, manifest, digest);
    const Status classified = classify(o);
    const bool usable = consistent && (o.status == Status::found || o.status == Status::not_present) &&
                        o.status == classified;
    const Status effective = usable ? o.status :
                             (o.status == Status::error || classified == Status::error ? Status::error : Status::unknown);
    if (effective != Status::found && effective != Status::not_present) ready = false;
    out += '{';
    field(out, "wallet_address", o.wallet.address); out += ',';
    field(out, "status", name(effective)); out += ',';
    field(out, "reported_status", name(o.status)); out += ',';
    field(out, "reason", !consistent ? "batch/manifest provenance mismatch or invalid tip" :
          usable ? o.reason : o.reason.empty() ? "unverified observation or missing caller proof/audit" : o.reason);
    out += ',';
    out += "\"wallet\":"; account(out, o.wallet); out += ',';
    out += "\"master\":"; account(out, o.master); out += ',';
    optional_field(out, "raw_signed_jetton_balance", o.raw_signed_balance); out += ',';
    optional_field(out, "owner", o.owner); out += ',';
    optional_field(out, "master_address_from_wallet", o.master_address); out += ',';
    optional_field(out, "getter_wallet_code_hash", o.getter_wallet_code_hash); out += ',';
    optional_field(out, "master_returned_wallet", o.master_returned_wallet); out += ',';
    field(out, "binding", name(o.binding)); out += ',';
    out += "\"source\":"; source(out, o.source); out += ',';
    out += "\"getter_context_audit\":"; audit(out, o.context_audit);
    out += '}';
    room(out, 0);
  }
  out += "],\"completion\":{";
  field(out, "status", ready ? "address_scope_ready" : "pending"); out += ',';
  bool_field(out, "address_scope_ready", ready); out += ',';
  field(out, "readiness_basis", "caller_attested_only"); out += ',';
  bool_field(out, "writer_committed", false); out += ',';
  bool_field(out, "publication_ready", false); out += ',';
  bool_field(out, "global_metric_complete", false); out += ',';
  bool_field(out, "daily_complete", false);
  out += "}}";
  room(out, 0);
  return out;
}

}  // namespace assets_analytics
