#include "WalletStage.h"

#include <stdexcept>
#include <string>
#include <utility>

namespace w = ton_analytics::wallets;
namespace e = ton_analytics::wallets::events;
namespace s = ton_analytics::wallets::stage;

namespace {
#define STAGE_EXPECT(condition) do { if (!(condition)) throw std::runtime_error("stage test failed: " #condition); } while (false)
constexpr auto zeros = "0000000000000000000000000000000000000000000000000000000000000000";
constexpr auto ones = "1111111111111111111111111111111111111111111111111111111111111111";
constexpr auto twos = "2222222222222222222222222222222222222222222222222222222222222222";
constexpr auto threes = "3333333333333333333333333333333333333333333333333333333333333333";
constexpr auto wallet_hash = "20834b7b72b112147e1b2fb457b84e74d1a30f04f737d4f62a668e9552d2b72f";
constexpr auto excluded_hash = "45ebbce9b5d235886cb6bfe1c3ad93b708de058244892365c9ee0dfe439cb7b5";

std::string b64(const std::string& hex) {
  static constexpr char alphabet[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string bytes;
  for (unsigned i = 0; i < 64; i += 2) bytes.push_back(static_cast<char>(std::stoi(hex.substr(i, 2), nullptr, 16)));
  std::string result;
  for (unsigned i = 0; i < 32; i += 3) {
    unsigned n = static_cast<unsigned char>(bytes[i]) << 16;
    if (i + 1 < 32) n |= static_cast<unsigned char>(bytes[i + 1]) << 8;
    if (i + 2 < 32) n |= static_cast<unsigned char>(bytes[i + 2]);
    result.push_back(alphabet[(n >> 18) & 63]);
    result.push_back(alphabet[(n >> 12) & 63]);
    result.push_back(i + 1 < 32 ? alphabet[(n >> 6) & 63] : '=');
    result.push_back(i + 2 < 32 ? alphabet[n & 63] : '=');
  }
  return result;
}

w::BlockId id(int wc, unsigned seq, const char* hash) {
  return {wc, 0x8000000000000000ULL, seq, hash, hash};
}
e::BlockId native(const w::BlockId& b) {
  return {b.workchain, static_cast<std::int64_t>(b.shard), b.seqno,
          b64(b.root_hash), b64(b.file_hash)};
}
e::TxId txid(const w::BlockId& mc, const w::BlockId& block, unsigned lt, unsigned now,
             const char* account = ones) {
  return {std::string("0:") + account, lt, twos, now, now - now % 86400,
          native(mc), native(block), zeros, threes};
}
e::CodeFact included() {
  return {e::Resolution::resolved, e::Classification::included_wallet, wallet_hash,
          "wallet_v5r1", "verified_pre_state"};
}
e::CodeFact excluded() {
  return {e::Resolution::resolved, e::Classification::excluded_code, excluded_hash,
          std::nullopt, "verified_post_state"};
}

struct Fixture {
  s::VerifiedEnvelope proof;
  e::Batch batch;
  Fixture() {
    const auto mc = id(-1, 2, ones), prev = id(-1, 1, zeros);
    const auto shard = id(0, 4, twos), parent = id(0, 3, threes);
    proof.scope = {"synthetic", zeros, ones, "v1", e::kRegistrySha256, {0}};
    proof.zerostate_mc = id(-1, 0, zeros);
    proof.zerostate_mc.file_hash = ones;
    proof.zerostate_anchor_verified = true;
    proof.zerostate_anchor_attestation = "independent-mc0";
    proof.mc = mc;
    proof.prev_mc = prev;
    proof.mc_utime = 86410;
    proof.first_included_shards = {{shard, {parent}, 86409}};
    proof.current_shard_tips = {{shard, 86409}};
    proof.graph_diff_verified = proof.time_rules_verified = proof.raw_inventory_verified = true;
    proof.graph_diff_attestation = "independent-graph";
    proof.time_rules_attestation = "independent-time";
    proof.raw_inventory_attestation = "independent-raw-txs";
    proof.raw_blocks = {{mc, 86410, true, true, true, {}},
                        {shard, 86409, true, true, true, {
                            {std::string("0:") + ones, 101, twos, zeros, threes, 86409,
                             w::AccountStatus::nonexist, w::AccountStatus::active, std::nullopt},
                            {std::string("0:") + twos, 102, twos, zeros, threes, 86409,
                             w::AccountStatus::active, w::AccountStatus::nonexist, threes},
                            {std::string("0:") + threes, 103, twos, zeros, threes, 86409,
                             w::AccountStatus::uninit, w::AccountStatus::active, std::nullopt},
                            {std::string("0:") + ones, 104, twos, zeros, threes, 86409,
                             w::AccountStatus::uninit, w::AccountStatus::active, std::nullopt},
                            {std::string("0:") + twos, 105, twos, zeros, threes, 86409,
                             w::AccountStatus::nonexist, w::AccountStatus::nonexist, threes}}}};
    batch.mc = native(mc);
    batch.included_blocks = {native(shard), native(mc)}; // scanner order is arbitrary
    batch.active_witnesses = {
        {txid(mc, shard, 101, 86409), schema::nonexist, schema::active, threes, false, excluded()},
        {txid(mc, shard, 102, 86409, twos), schema::active, schema::nonexist, threes, false, {}},
        {txid(mc, shard, 103, 86409, threes), schema::uninit, schema::active, threes, true, included()},
        {txid(mc, shard, 104, 86409), schema::uninit, schema::active, threes, true, {}}};
    batch.pending_post_codes = 1;
    batch.sends = {{txid(mc, shard, 102, 86409, twos), threes, included()},
                   {txid(mc, shard, 105, 86409, twos), threes, {}}};
    batch.pending_execution_codes = 1;
  }
};

template <class F> void rejected(F&& f) {
  bool threw = false;
  try { f(); } catch (const std::invalid_argument&) { threw = true; }
  STAGE_EXPECT(threw);
}

void acceptance() {
  Fixture f;
  const auto out = s::build(f.proof, f.batch);
  STAGE_EXPECT(out.scope.zerostate_root_hash == zeros && out.scope.zerostate_file_hash == ones);
  STAGE_EXPECT(out.mc_transactions_complete && out.new_shard_blocks[0].transactions_complete);
  STAGE_EXPECT(!out.new_shard_blocks[0].activation_inputs_complete); // unresolved first activation
  STAGE_EXPECT(!out.new_shard_blocks[0].activity_inputs_complete); // unresolved send
  STAGE_EXPECT(out.observations.size() == 5);
  STAGE_EXPECT(out.observations[0].orig == w::AccountStatus::nonexist);
  bool found_destroy = false, found_send_only = false, found_pending = false;
  for (const auto& o : out.observations) {
    if (o.lt == 101) {
      STAGE_EXPECT(o.orig == w::AccountStatus::nonexist && o.end == w::AccountStatus::active);
      STAGE_EXPECT(o.activation_code.kind == w::EvidenceKind::excluded);
    }
    if (o.lt == 103) {
      STAGE_EXPECT(o.orig == w::AccountStatus::uninit && o.end == w::AccountStatus::active);
      STAGE_EXPECT(o.activation_code.kind == w::EvidenceKind::qualified &&
                   o.activation_code.wallet_type_id == "wallet_v5r1");
    }
    if (o.lt == 102) {
      found_destroy = true;
      STAGE_EXPECT(o.end == w::AccountStatus::nonexist && o.actual_qualifying_outgoing);
      STAGE_EXPECT(o.execution_code.kind == w::EvidenceKind::qualified &&
             o.outgoing_message_hash == threes);
    }
    if (o.lt == 105) {
      found_send_only = true;
      STAGE_EXPECT(o.actual_qualifying_outgoing && o.execution_code.kind == w::EvidenceKind::unknown);
    }
    if (o.lt == 104) {
      found_pending = true;
      STAGE_EXPECT(o.activation_code.kind == w::EvidenceKind::unknown);
    }
  }
  STAGE_EXPECT(found_destroy && found_send_only && found_pending);
  // No lifetime baseline is created here: reducer must never mint firstness from a two-MC pilot.
  w::WalletMetrics reducer(f.proof.scope);
  reducer.put(out);
  STAGE_EXPECT(!reducer.first_active(std::string("0:") + ones));
  const auto day = reducer.day(86400);
  STAGE_EXPECT(!day.daily_activations && !day.cumulative_activations && !day.dau && !day.mau_30d);
}

void failures() {
  // The stage validates encoding of BOTH genesis hashes, not just one identity.
  rejected([] { Fixture f; f.proof.scope.zerostate_root_hash.clear(); s::build(f.proof, f.batch); });
  rejected([] { Fixture f; f.proof.scope.zerostate_file_hash = "bad-file-hash";
               s::build(f.proof, f.batch); });
  rejected([] { Fixture f; f.proof.scope.zerostate_root_hash[0] = 'z'; s::build(f.proof, f.batch); });
  rejected([] { Fixture f; f.proof.scope.zerostate_file_hash[0] = 'z'; s::build(f.proof, f.batch); });
  rejected([] { Fixture f; f.proof.scope.zerostate_root_hash = twos; s::build(f.proof, f.batch); });
  rejected([] { Fixture f; f.proof.scope.zerostate_file_hash = twos; s::build(f.proof, f.batch); });
  rejected([] { Fixture f; f.proof.zerostate_mc.root_hash = twos; s::build(f.proof, f.batch); });
  rejected([] { Fixture f; f.proof.zerostate_mc.file_hash = twos; s::build(f.proof, f.batch); });
  rejected([] { Fixture f; f.proof.zerostate_mc.seqno = 1; s::build(f.proof, f.batch); });
  rejected([] { Fixture f; f.proof.zerostate_anchor_verified = false; s::build(f.proof, f.batch); });
  // Two different, syntactically valid genesis IDs are different reducer scopes.
  rejected([] { Fixture f; auto out = s::build(f.proof, f.batch); auto scope = f.proof.scope;
               scope.zerostate_root_hash = twos; w::WalletMetrics reducer(scope); reducer.put(out); });
  rejected([] { Fixture f; auto out = s::build(f.proof, f.batch); auto scope = f.proof.scope;
               scope.zerostate_file_hash = twos; w::WalletMetrics reducer(scope); reducer.put(out); });
  // Even a valid V5R1 post-code cannot excuse a missing/incorrect native HASH_UPDATE.
  rejected([] { Fixture f; f.proof.raw_blocks[1].transactions[2].pre_state_hash_hex.clear();
               s::build(f.proof, f.batch); });
  rejected([] { Fixture f; f.proof.raw_blocks[1].transactions[2].post_state_hash_hex = ones;
               s::build(f.proof, f.batch); });
  rejected([] { Fixture f; f.batch.active_witnesses[2].tx.pre_state_hash_hex = ones;
               s::build(f.proof, f.batch); });
  rejected([] { Fixture f; f.batch.active_witnesses[2].tx.post_state_hash_hex.clear();
               s::build(f.proof, f.batch); });
  rejected([] { Fixture f; f.batch.active_witnesses[2].post_state_hash_hex = zeros;
               s::build(f.proof, f.batch); });
  rejected([] { Fixture f; f.batch.sends[0].tx.pre_state_hash_hex = ones;
               s::build(f.proof, f.batch); });
  rejected([] { Fixture f; f.batch.sends[0].tx.post_state_hash_hex = zeros;
               s::build(f.proof, f.batch); });
  rejected([] { Fixture f; f.batch.sends[1].tx.pre_state_hash_hex.clear();
               s::build(f.proof, f.batch); });
  rejected([] { Fixture f; f.proof.raw_blocks[1].transactions[4].post_state_hash_hex.clear();
               s::build(f.proof, f.batch); });
  rejected([] { Fixture f; f.proof.raw_blocks.pop_back(); s::build(f.proof, f.batch); });
  rejected([] { Fixture f; f.proof.raw_blocks[1].outgoing_complete = false; s::build(f.proof, f.batch); });
  rejected([] { Fixture f; f.proof.raw_blocks[1].transactions.pop_back(); s::build(f.proof, f.batch); });
  rejected([] { Fixture f; f.proof.raw_blocks[1].transactions[1].first_qualifying_message_hash_hex.reset();
               s::build(f.proof, f.batch); });
  rejected([] { Fixture f; f.batch.sends.pop_back(); f.batch.pending_execution_codes = 0;
               s::build(f.proof, f.batch); });
  rejected([] { Fixture f; f.batch.active_witnesses.erase(f.batch.active_witnesses.begin());
               s::build(f.proof, f.batch); });
  rejected([] { Fixture f; f.batch.active_witnesses.push_back(f.batch.active_witnesses.front());
               s::build(f.proof, f.batch); });
  rejected([] { Fixture f; f.batch.included_blocks.pop_back(); s::build(f.proof, f.batch); });
  rejected([] { Fixture f; f.batch.included_blocks.push_back(f.batch.included_blocks.front());
               s::build(f.proof, f.batch); });
  rejected([] { Fixture f; f.batch.registry_sha256 = "previous-registry"; s::build(f.proof, f.batch); });
  rejected([] { Fixture f; f.proof.graph_diff_verified = false; s::build(f.proof, f.batch); });
  rejected([] { Fixture f; f.proof.raw_inventory_attestation = f.proof.graph_diff_attestation;
               s::build(f.proof, f.batch); });
  rejected([] { Fixture f; f.batch.active_witnesses[0].tx.shard.file_hash[0] = '-';
               s::build(f.proof, f.batch); });
  rejected([] { Fixture f; f.batch.active_witnesses[0].tx.now++;
               s::build(f.proof, f.batch); });
  rejected([] { Fixture f; f.batch.sends[0].message_hash_hex = ones; s::build(f.proof, f.batch); });
  rejected([] { Fixture f; f.batch.pending_post_codes = 0; s::build(f.proof, f.batch); });
  rejected([] { Fixture f; f.batch.active_witnesses[2].post_code.wallet_type_id = "wallet_v4r2";
               s::build(f.proof, f.batch); });
  rejected([] { Fixture f; f.batch.active_witnesses[0].post_code.classification =
                   e::Classification::outside_registry; s::build(f.proof, f.batch); });
  rejected([] { Fixture f; f.proof.first_included_shards[0].predecessors.push_back(
                   f.proof.first_included_shards[0].predecessors[0]); s::build(f.proof, f.batch); });
  rejected([] { Fixture f; f.proof.raw_blocks[1].transactions[0].orig =
                   static_cast<w::AccountStatus>(99); s::build(f.proof, f.batch); });
  rejected([] { Fixture f; f.proof.current_shard_tips.push_back(f.proof.current_shard_tips[0]);
               s::build(f.proof, f.batch); });
  bool capped = false;
  try { Fixture f; s::build(f.proof, f.batch, {1, 2, 5}); }
  catch (const std::length_error&) { capped = true; }
  STAGE_EXPECT(capped);
}
} // namespace

int main() {
  acceptance();
  failures();
}
