#include "WalletStage.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <map>
#include <set>
#include <stdexcept>
#include <tuple>
#include <utility>

namespace ton_analytics::wallets::stage {
namespace {

void require(bool ok, const char* why) {
  if (!ok) throw std::invalid_argument(why);
}

int nibble(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

std::string hex256(const std::string& value) {
  require(value.size() == 64, "expected 256-bit hex hash");
  std::string out = value;
  for (char& c : out) {
    require(nibble(c) >= 0, "non-hex hash");
    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  }
  return out;
}

// Strict standard base64 of exactly 32 bytes. Reject noncanonical trailing bits,
// URL-safe, whitespace and extra padding; no native decoder or native link needed.
std::string b64_hash(const std::string& encoded) {
  require(encoded.size() == 44 && encoded[43] == '=', "expected 32-byte base64 hash");
  const auto digit = [](char c) -> int {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
  };
  static constexpr char alphabet[] = "0123456789abcdef";
  std::string out;
  out.reserve(64);
  for (std::size_t i = 0; i < 44; i += 4) {
    int a = digit(encoded[i]), b = digit(encoded[i + 1]), c = digit(encoded[i + 2]);
    require(a >= 0 && b >= 0 && c >= 0, "invalid base64 hash");
    const bool last = i == 40;
    int d = last ? 0 : digit(encoded[i + 3]);
    require(d >= 0 && (!last || (c & 3) == 0), "noncanonical base64 hash");
    const unsigned value = (static_cast<unsigned>(a) << 18) | (static_cast<unsigned>(b) << 12) |
                           (static_cast<unsigned>(c) << 6) | static_cast<unsigned>(d);
    for (unsigned n = 0; n < (last ? 2u : 3u); ++n) {
      const unsigned byte = (value >> (16 - n * 8)) & 255;
      out.push_back(alphabet[byte >> 4]);
      out.push_back(alphabet[byte & 15]);
    }
  }
  return out;
}

std::string address(const std::string& raw) {
  require(raw.size() <= 76, "oversized raw address");
  const auto colon = raw.find(':');
  require(colon != std::string::npos && colon != 0 && colon != raw.size() - 1 &&
              raw.find(':', colon + 1) == std::string::npos, "invalid raw address");
  auto prefix = raw.substr(0, colon);
  require(prefix == "0" || (prefix[0] == '-' && prefix.size() > 1) ||
              (prefix[0] >= '1' && prefix[0] <= '9'), "invalid address workchain");
  const auto start = prefix[0] == '-' ? 1u : 0u;
  require(prefix.substr(start) == "0" || prefix[start] != '0', "noncanonical address workchain");
  for (std::size_t i = start; i < prefix.size(); ++i)
    require(prefix[i] >= '0' && prefix[i] <= '9', "invalid address workchain");
  require(prefix != "-0", "negative zero workchain");
  // Avoid unbounded/overflowing workchain names; std::stoi checks int32_t.
  require(prefix.size() <= 11, "address workchain out of range");
  try { (void)std::stoi(prefix); }
  catch (const std::exception&) { throw std::invalid_argument("address workchain out of range"); }
  return prefix + ":" + hex256(raw.substr(colon + 1));
}

BlockId canonical(BlockId id) {
  id.root_hash = hex256(id.root_hash);
  id.file_hash = hex256(id.file_hash);
  return id;
}

BlockId native_id(const events::BlockId& id) {
  return {id.workchain, static_cast<std::uint64_t>(id.shard), id.seqno,
          b64_hash(id.root_hash), b64_hash(id.file_hash)};
}

AccountStatus status(schema::AccountStatus status) {
  switch (status) {
    case schema::nonexist: return AccountStatus::nonexist;
    case schema::uninit: return AccountStatus::uninit;
    case schema::active: return AccountStatus::active;
    case schema::frozen: return AccountStatus::frozen;
  }
  throw std::invalid_argument("unrecognized native status");
}

bool valid_status(AccountStatus status) {
  switch (status) {
    case AccountStatus::nonexist:
    case AccountStatus::uninit:
    case AccountStatus::active:
    case AccountStatus::frozen: return true;
  }
  return false;
}

CodeEvidence code(const events::CodeFact& fact) {
  require(fact.source.size() <= 256 && (!fact.wallet_type_id || fact.wallet_type_id->size() <= 64),
          "oversized code provenance/type");
  CodeEvidence out;
  out.source = fact.source; // preserve unresolved provenance, including replay errors
  if (fact.classification == events::Classification::pending) {
    require(!fact.code_hash_hex && !fact.wallet_type_id &&
                fact.resolution != events::Resolution::resolved, "ambiguous pending code");
    return out;
  }
  require(fact.resolution == events::Resolution::resolved && fact.code_hash_hex &&
              !fact.source.empty(), "unverified resolved code");
  out.code_hash = hex256(*fact.code_hash_hex);
  // Lock the reducer's wallet/type relation to this versioned extractor registry,
  // rather than accepting an internally inconsistent producer CodeFact.
  static constexpr std::array<std::pair<const char*, const char*>, 19> registry{{
        {"a0cfc2c48aee16a271f2cfc0b7382d81756cecb1017d077faaab3bb602f6868c", "wallet_v1r1"},
        {"d4902fcc9fad74698fa8e353220a68da0dcf72e32bcb2eb9ee04217c17d3062c", "wallet_v1r2"},
        {"587cc789eff1c84f46ec3797e45fc809a14ff5ae24f1e0c7a6a99cc9dc9061ff", "wallet_v1r3"},
        {"5c9a5e68c108e18721a07c42f9956bfb39ad77ec6d624b60c576ec88eee65329", "wallet_v2r1"},
        {"fe9530d3243853083ef2ef0b4c2908c0abf6fa1c31ea243aacaa5bf8c7d753f1", "wallet_v2r2"},
        {"b61041a58a7980b946e8fb9e198e3c904d24799ffa36574ea4251c41a566f581", "wallet_v3r1"},
        {"84dafa449f98a6987789ba232358072bc0f76dc4524002a5d0918b9a75d2d599", "wallet_v3r2"},
        {"64dd54805522c5be8a9db59cea0105ccf0d08786ca79beb8cb79e880a8d7322d", "wallet_v4r1"},
        {"feb5ff6820e2ff0d9483e7e0d62c817d846789fb4ae580c878866d959dabd5c0", "wallet_v4r2"},
        {"e4cf3b2f4c6d6a61ea0f2b5447d266785b26af3637db2deee6bcd1aa826f3412", "wallet_v5_beta"},
        {"f3d7ca53493deedac28b381986a849403cbac3d2c584779af081065af0ac4b93", "wallet_v5_beta"},
        {"20834b7b72b112147e1b2fb457b84e74d1a30f04f737d4f62a668e9552d2b72f", "wallet_v5r1"},
        {"d8cdbbb79f2c5caa677ac450770be0351be21e1250486de85cc52aa33dd16484", "wallet_highload_v1r1"},
        {"0dceed21269d66013e95b19fbb5c55a6f01adad40837baa8e521cde3a02aa46c", "wallet_highload_v1r2"},
        {"9494d1cc8edf12f05671a1a9ba09921096eb50811e1924ec65c3c629fbb80812", "wallet_highload_v2"},
        {"8ceb45b3cd4b5cc60eaae1c13b9c092392677fe536b2e9b2d801b62eff931fe1", "wallet_highload_v2r1"},
        {"203dd4f358adb49993129aa925cac39916b68a0e4f78d26e8f2c2b69eafa5679", "wallet_highload_v2r2"},
        {"11acad7955844090f283bf238bc1449871f783e7cc0979408d3f4859483e8525", "wallet_highload_v3r1"},
        {"9149ae51c1e4689710cebf7830297b16acfbadb363a920a537893e7ffeeca768", "wallet_tg"},
  }};
  const auto known = std::find_if(registry.begin(), registry.end(), [&](const auto& entry) {
    return out.code_hash == entry.first;
  });
  const bool excluded = out.code_hash == "45ebbce9b5d235886cb6bfe1c3ad93b708de058244892365c9ee0dfe439cb7b5" ||
                        out.code_hash == "b48b531abec3b714638291f7d77ed6dc9f6a2729efca20477137374d4ae8b590" ||
                        out.code_hash == "43d44716d326a832ced56a6b60a02cb67630e04f5785fe89f8784a110cf36151";
  if (fact.classification == events::Classification::included_wallet) {
    require(fact.wallet_type_id && !fact.wallet_type_id->empty(), "wallet without registry type");
    require(known != registry.end() && *fact.wallet_type_id == known->second,
            "code hash/type disagrees with pinned registry");
    out.kind = EvidenceKind::qualified;
    out.wallet_type_id = *fact.wallet_type_id;
  } else {
    require(!fact.wallet_type_id &&
                (fact.classification == events::Classification::excluded_code ||
                 fact.classification == events::Classification::outside_registry),
            "ambiguous excluded code");
    require(fact.classification == events::Classification::excluded_code ? excluded :
                (!excluded && known == registry.end()), "code classification disagrees with pinned registry");
    out.kind = EvidenceKind::excluded; // known hash outside selected registry, not globally non-wallet
  }
  return out;
}

using TxKey = std::pair<std::string, std::uint64_t>;
TxKey key(const std::string& account_raw, std::uint64_t lt) {
  return {address(account_raw), lt};
}

struct TxSource {
  BlockId block;
  RawTransaction tx;
  bool witness = false;
  bool send = false;
};

void check_identity(const events::TxId& id, const TxSource& raw, const BlockId& mc) {
  require(native_id(id.mc) == mc && native_id(id.shard) == raw.block &&
              hex256(id.hash_hex) == hex256(raw.tx.hash_hex) && id.now == raw.tx.now &&
              hex256(id.pre_state_hash_hex) == hex256(raw.tx.pre_state_hash_hex) &&
              hex256(id.post_state_hash_hex) == hex256(raw.tx.post_state_hash_hex) &&
              id.utc_day_start == id.now - id.now % 86400 &&
              address(id.account) == address(raw.tx.account) && id.lt == raw.tx.lt,
          "extractor tx identity/HASH_UPDATE disagrees with independent raw inventory");
}

} // namespace

BlockEnvelope build(const VerifiedEnvelope& verified, const events::Batch& batch, Limits limits) {
  require(limits.max_blocks && limits.max_tips && limits.max_transactions, "invalid stage limits");
  if (verified.first_included_shards.size() >= limits.max_blocks ||
      verified.raw_blocks.size() > limits.max_blocks ||
      batch.included_blocks.size() > limits.max_blocks ||
      verified.current_shard_tips.size() > limits.max_tips ||
      batch.active_witnesses.size() > limits.max_transactions ||
      batch.sends.size() > limits.max_transactions)
    throw std::length_error("wallet stage block/tip/transaction cap exceeded");
  require(verified.scope.registry_sha256 == events::kRegistrySha256 &&
              batch.registry_sha256 == events::kRegistrySha256,
          "wallet registry SHA mismatch");
  require(!verified.scope.network.empty() && !verified.scope.calc_version.empty() &&
              !verified.scope.workchains.empty() && verified.scope.network.size() <= 128 &&
              verified.scope.calc_version.size() <= 128, "incomplete/oversized wallet scope");
  (void)hex256(verified.scope.zerostate_root_hash);
  (void)hex256(verified.scope.zerostate_file_hash);
  require(verified.graph_diff_verified && verified.time_rules_verified &&
              verified.raw_inventory_verified && verified.zerostate_anchor_verified &&
              !verified.zerostate_anchor_attestation.empty() &&
              verified.zerostate_anchor_attestation.size() <= 256 &&
              !verified.graph_diff_attestation.empty() &&
              !verified.time_rules_attestation.empty() && !verified.raw_inventory_attestation.empty() &&
              verified.graph_diff_attestation.size() <= 256 &&
              verified.time_rules_attestation.size() <= 256 &&
              verified.raw_inventory_attestation.size() <= 256 &&
              verified.graph_diff_attestation != verified.time_rules_attestation &&
              verified.graph_diff_attestation != verified.raw_inventory_attestation &&
              verified.time_rules_attestation != verified.raw_inventory_attestation &&
              verified.zerostate_anchor_attestation != verified.graph_diff_attestation &&
              verified.zerostate_anchor_attestation != verified.time_rules_attestation &&
              verified.zerostate_anchor_attestation != verified.raw_inventory_attestation,
          "missing independent coverage attestations");

  BlockEnvelope out;
  out.scope = verified.scope;
  out.scope.zerostate_root_hash = hex256(out.scope.zerostate_root_hash);
  out.scope.zerostate_file_hash = hex256(out.scope.zerostate_file_hash);
  const auto genesis = canonical(verified.zerostate_mc);
  out.mc = canonical(verified.mc);
  out.prev_mc = canonical(verified.prev_mc);
  require(genesis.workchain == -1 && genesis.seqno == 0 &&
              genesis.shard == out.mc.shard &&
              genesis.root_hash == out.scope.zerostate_root_hash &&
              genesis.file_hash == out.scope.zerostate_file_hash &&
              out.mc.workchain == -1 && out.prev_mc.workchain == -1 &&
              out.mc.shard == out.prev_mc.shard && out.mc.seqno != 0 &&
              out.mc.seqno == out.prev_mc.seqno + 1 &&
              native_id(batch.mc) == out.mc && verified.mc_utime >= 0,
          "unverified MC identity/ancestry");
  out.mc_utime = verified.mc_utime;
  out.revision = verified.revision;

  std::map<BlockId, std::int64_t> sources{{out.mc, out.mc_utime}};
  std::set<std::tuple<std::int32_t, std::uint64_t, std::uint32_t>> coordinates;
  coordinates.emplace(out.mc.workchain, out.mc.shard, out.mc.seqno);
  for (auto b : verified.first_included_shards) {
    b.id = canonical(b.id);
    require(b.id.workchain != -1 && out.scope.workchains.contains(b.id.workchain) &&
                b.gen_utime >= 0 && !b.predecessors.empty() && b.predecessors.size() <= 2,
            "invalid first-included shard graph");
    std::set<BlockId> parents;
    for (auto& p : b.predecessors) {
      p = canonical(p);
      require(p.workchain == b.id.workchain && p.seqno < b.id.seqno &&
                  parents.insert(p).second, "invalid/duplicate shard predecessor");
    }
    require(sources.emplace(b.id, b.gen_utime).second &&
                coordinates.emplace(b.id.workchain, b.id.shard, b.id.seqno).second,
            "duplicate first-included block/coordinate");
    // These booleans must come from inventory below, never from caller's graph or Batch.
    b.transactions_complete = b.activation_inputs_complete = b.activity_inputs_complete = false;
    out.new_shard_blocks.push_back(std::move(b));
  }
  std::set<BlockId> tips;
  std::set<std::tuple<std::int32_t, std::uint64_t, std::uint32_t>> tip_coordinates;
  std::set<std::int32_t> tip_workchains;
  for (auto tip : verified.current_shard_tips) {
    tip.id = canonical(tip.id);
    require(out.scope.workchains.contains(tip.id.workchain) && tip.gen_utime >= 0 &&
                tips.insert(tip.id).second &&
                tip_coordinates.emplace(tip.id.workchain, tip.id.shard, tip.id.seqno).second,
            "duplicate/conflicting or unexpected current shard tip");
    tip_workchains.insert(tip.id.workchain);
    out.current_shard_tips.push_back(std::move(tip));
  }
  require(tip_workchains == out.scope.workchains, "incomplete current tip manifest");
  for (const auto& b : out.new_shard_blocks)
    for (const auto& p : b.predecessors) {
      auto parent = sources.find(p);
      if (parent != sources.end())
        require(b.gen_utime >= parent->second, "nonmonotonic first-included predecessor time");
    }

  std::set<BlockId> batch_ids;
  for (const auto& id : batch.included_blocks)
    require(batch_ids.insert(native_id(id)).second, "duplicate extractor source block");
  require(batch_ids.size() == sources.size(), "extractor source block count differs from graph");
  for (const auto& [id, utime] : sources)
    require(batch_ids.contains(id), "missing or extra extractor first-included block");

  std::map<BlockId, std::pair<bool, bool>> complete;
  std::map<TxKey, TxSource> raw;
  for (const auto& inventory : verified.raw_blocks) {
    auto id = canonical(inventory.id);
    auto source = sources.find(id);
    require(source != sources.end() && source->second == inventory.gen_utime &&
                inventory.transactions_complete && inventory.statuses_complete &&
                inventory.outgoing_complete && complete.emplace(id, std::make_pair(true, true)).second,
            "incomplete, duplicate or mismatched raw block inventory");
    if (inventory.transactions.size() > limits.max_transactions - raw.size())
      throw std::length_error("wallet stage raw transaction cap exceeded");
    for (const auto& tx : inventory.transactions) {
      require(tx.now == inventory.gen_utime && tx.lt != 0 &&
                  valid_status(tx.orig) && valid_status(tx.end), "raw tx/block status or time mismatch");
      auto account = address(tx.account);
      require(std::stoi(account.substr(0, account.find(':'))) == id.workchain,
              "raw tx account workchain disagrees with source block");
      (void)hex256(tx.hash_hex);
      (void)hex256(tx.pre_state_hash_hex);
      (void)hex256(tx.post_state_hash_hex);
      if (tx.first_qualifying_message_hash_hex) (void)hex256(*tx.first_qualifying_message_hash_hex);
      require(raw.emplace(TxKey{std::move(account), tx.lt}, TxSource{id, tx}).second,
              "duplicate (address,LT) in raw inventory");
    }
  }
  require(complete.size() == sources.size(), "missing raw block inventory (including empty blocks)");
  require(batch.active_witnesses.size() <= raw.size() && batch.sends.size() <= raw.size(),
          "extractor events exceed raw tx count");

  std::map<TxKey, WalletObservation> observations;
  std::size_t pending_post = 0, pending_exec = 0;
  for (const auto& w : batch.active_witnesses) {
    auto found = raw.find(key(w.tx.account, w.tx.lt));
    require(found != raw.end() && !found->second.witness, "extra or duplicate active witness");
    auto& source = found->second;
    check_identity(w.tx, source, out.mc);
    require(source.tx.orig == status(w.orig_status) && source.tx.end == status(w.end_status) &&
                (source.tx.orig == AccountStatus::active || source.tx.end == AccountStatus::active) &&
                w.activation_candidate == (source.tx.orig == AccountStatus::uninit &&
                                           source.tx.end == AccountStatus::active),
            "active witness/status mismatch");
    require(hex256(w.post_state_hash_hex) == hex256(source.tx.post_state_hash_hex),
            "active witness post-state HASH_UPDATE mismatch");
    auto activation = code(w.post_code);
    if (source.tx.end == AccountStatus::active && activation.kind == EvidenceKind::unknown) {
      ++pending_post;
      complete.at(source.block).first = false;
    }
    require(source.tx.end == AccountStatus::active || activation.kind == EvidenceKind::unknown,
            "post code attached to absent post-state");
    source.witness = true;
    observations.emplace(found->first, WalletObservation{found->first.first, w.tx.lt,
        hex256(w.tx.hash_hex), w.tx.now, source.block, source.tx.orig, source.tx.end,
        std::move(activation), {}, false, {}});
  }
  for (const auto& s : batch.sends) {
    auto found = raw.find(key(s.tx.account, s.tx.lt));
    require(found != raw.end() && !found->second.send, "extra or duplicate qualifying send");
    auto& source = found->second;
    check_identity(s.tx, source, out.mc);
    require(source.tx.first_qualifying_message_hash_hex &&
                hex256(*source.tx.first_qualifying_message_hash_hex) == hex256(s.message_hash_hex),
            "qualifying send absent/mismatched in raw out-message inventory");
    auto execution = code(s.execution_code);
    if (execution.kind == EvidenceKind::unknown) {
      ++pending_exec;
      complete.at(source.block).second = false;
    }
    source.send = true;
    auto [o, inserted] = observations.try_emplace(found->first);
    if (inserted) {
      o->second = {found->first.first, s.tx.lt, hex256(s.tx.hash_hex), s.tx.now,
                   source.block, source.tx.orig, source.tx.end, {}, {}, false, {}};
    }
    o->second.execution_code = std::move(execution);
    o->second.actual_qualifying_outgoing = true;
    o->second.outgoing_message_hash = hex256(s.message_hash_hex);
  }
  for (const auto& [id, source] : raw) {
    require(source.witness == (source.tx.orig == AccountStatus::active ||
                               source.tx.end == AccountStatus::active),
            "omitted active witness in extractor batch");
    require(source.send == source.tx.first_qualifying_message_hash_hex.has_value(),
            "omitted qualifying send in extractor batch");
  }
  require(batch.pending_post_codes == pending_post && batch.pending_execution_codes == pending_exec,
          "extractor pending counters inconsistent with events");
  for (auto& [id, o] : observations) out.observations.push_back(std::move(o));
  out.mc_transactions_complete = true;
  out.mc_activation_inputs_complete = complete.at(out.mc).first;
  out.mc_activity_inputs_complete = complete.at(out.mc).second;
  for (auto& b : out.new_shard_blocks) {
    b.transactions_complete = true;
    b.activation_inputs_complete = complete.at(b.id).first;
    b.activity_inputs_complete = complete.at(b.id).second;
  }
  out.graph_diff_verified = verified.graph_diff_verified;
  out.time_rules_verified = verified.time_rules_verified;
  out.graph_diff_attestation = verified.graph_diff_attestation;
  out.time_rules_attestation = verified.time_rules_attestation;
  out.tx_inventory_attestation = verified.raw_inventory_attestation;
  return out;
}

} // namespace ton_analytics::wallets::stage
