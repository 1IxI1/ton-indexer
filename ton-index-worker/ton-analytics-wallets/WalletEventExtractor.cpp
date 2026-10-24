#include "WalletEventExtractor.h"

#include "td/utils/base64.h"
#include "vm/db/DynamicBagOfCellsDb.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <set>
#include <stdexcept>
#include <tuple>
#include <utility>

namespace ton_analytics::wallets::events {
namespace {

using RegistryEntry = std::pair<const char*, const char*>;
constexpr std::array<RegistryEntry, 19> kRegistry{{
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
constexpr std::array<const char*, 3> kExcluded{{
    "45ebbce9b5d235886cb6bfe1c3ad93b708de058244892365c9ee0dfe439cb7b5", // preprocessed v2
    "b48b531abec3b714638291f7d77ed6dc9f6a2729efca20477137374d4ae8b590", // vesting
    "43d44716d326a832ced56a6b60a02cb67630e04f5785fe89f8784a110cf36151", // x1000
}};

BlockId id_of(const schema::Block& b) {
  return {b.workchain, b.shard, b.seqno, b.root_hash, b.file_hash};
}
auto id_key(const BlockId& b) {
  return std::make_tuple(b.workchain, b.shard, b.seqno, b.root_hash, b.file_hash);
}
auto coordinate(const BlockId& b) { return std::make_tuple(b.workchain, b.shard, b.seqno); }
std::string raw_address(const block::StdAddress& a) {
  return std::to_string(a.workchain) + ":" + a.addr.to_hex();
}

bool activated_by_message(const schema::Transaction& tx) {
  if (tx.orig_status != schema::uninit && tx.orig_status != schema::nonexist) return false;
  if (tx.end_status != schema::active || !tx.in_msg || tx.in_msg->init_state.is_null() ||
      !tx.in_msg->destination || *tx.in_msg->destination != raw_address(tx.account)) return false;
  // Both internal and external-in have a destination. Do not accept an external-out
  // (no destination) or an internally inconsistent message as a deployment proof.
  if (tx.in_msg->bounced && *tx.in_msg->bounced) return false;
  const auto* ord = std::get_if<schema::TransactionDescr_ord>(&tx.description);
  const auto* tick = std::get_if<schema::TransactionDescr_tick_tock>(&tx.description);
  const schema::TrComputePhase* compute = ord ? &ord->compute_ph : (tick ? &tick->compute_ph : nullptr);
  if (!compute || (ord && ord->aborted) || (tick && tick->aborted)) return false;
  const auto* vm = std::get_if<schema::TrComputePhase_vm>(compute);
  return vm && vm->success && vm->msg_state_used && vm->account_activated;
}

CodeEvidence applied_init(const schema::Transaction& tx) {
  if (!activated_by_message(tx)) return {};
  block::gen::StateInit::Record state_init;
  if (!tlb::unpack_cell(tx.in_msg->init_state, state_init)) return {};
  auto code = state_init.code;
  if (code.is_null() || code.write().fetch_ulong(1) != 1 || code->size_refs() == 0) return {};
  auto cell = code->prefetch_ref();
  if (cell.is_null()) return {};
  return {Resolution::resolved, cell->get_hash().bits(), tx.account_state_hash_after,
          "applied_message_state_init:vm_account_activated", true};
}

// A parsed AccountState is only a matching immutable endpoint when its address AND
// Account-cell hash match HASH_UPDATE. In today's parser this is usually the LAST
// post-state in a block, not every intermediate state. Never use it by address alone.
CodeEvidence parsed_state(const schema::Transaction& tx, CodeUse use,
                          const std::vector<schema::AccountState>& states) {
  if (use == CodeUse::execution && tx.orig_status != schema::active) return {};
  if (use == CodeUse::post_state && tx.end_status != schema::active) return {};
  const auto expected = use == CodeUse::execution ? tx.account_state_hash_before
                                                   : tx.account_state_hash_after;
  for (const auto& state : states) {
    if (state.account != tx.account || state.hash != expected) continue;
    if (use == CodeUse::post_state && (state.last_trans_lt != tx.lt || state.last_trans_hash != tx.hash))
      continue;
    if (state.account_status == "nonexist" || state.account_status == "uninit" ||
        state.account_status == "frozen") {
      return {}; // conflicts with the tx's asserted active endpoint; not a negative wallet proof
    }
    if (state.account_status == "active" && state.code_hash && !state.code.is_null() &&
        td::Bits256(state.code->get_hash().bits()) == *state.code_hash) {
      return {Resolution::resolved, state.code_hash, expected, "parsed_exact_account_state", true};
    }
  }
  return {};
}

CodeEvidence resolve_code(const schema::Transaction& tx, CodeUse use,
                          const std::vector<schema::AccountState>& states,
                          VerifiedCodeResolver& resolver) {
  if (use == CodeUse::execution) {
    auto deployed = applied_init(tx);
    if (deployed.resolution == Resolution::resolved) return deployed;
    if (tx.orig_status != schema::active)
      return {Resolution::unavailable, std::nullopt, tx.account_state_hash_before,
              "deployment_state_init_not_proven_applied", false};
  }
  auto local = parsed_state(tx, use, states);
  if (local.resolution != Resolution::unavailable) return local;
  auto remote = resolver.resolve(tx, use);
  const auto expected = use == CodeUse::execution ? tx.account_state_hash_before
                                                   : tx.account_state_hash_after;
  // A pre-state must be ACTIVE to provide execution code. An uninit execution
  // code is valid only with the proved applied-init path above.
  if (use == CodeUse::post_state && tx.end_status != schema::active)
    return {Resolution::unsupported, std::nullopt, expected, "post_state_not_active", false};
  if (!remote.verified || remote.state_hash != expected || remote.source.empty() ||
      (remote.resolution == Resolution::resolved && !remote.code_hash)) {
    if (remote.resolution != Resolution::resolved && !remote.source.empty()) {
      remote.code_hash.reset();
      return remote; // preserve unavailable/unsupported/replay_error reason as pending
    }
    return {Resolution::unsupported, std::nullopt, expected,
            "resolver_proof_mismatch_or_unverified", false};
  }
  return remote;
}

bool qualifying(const schema::Message& m, const std::string& address) {
  if (!m.source || *m.source != address) return false;
  // Parsed internal messages have bounced set, even when bounce=true.
  // Parsed external-out messages have no destination and no bounced bit.
  if (m.bounced.has_value()) return m.destination.has_value() && m.bounce.has_value() && !*m.bounced;
  return !m.destination.has_value() && !m.bounce.has_value();
}

} // namespace

CellDbVerifiedResolver::CellDbVerifiedResolver(std::shared_ptr<vm::CellDbReader> reader)
    : reader_(std::move(reader)) {
}

CodeEvidence CellDbVerifiedResolver::resolve(const schema::Transaction& tx, CodeUse use) {
  const auto expected = use == CodeUse::execution ? tx.account_state_hash_before
                                                   : tx.account_state_hash_after;
  auto pending = [&](Resolution why, const char* source) -> CodeEvidence {
    return {why, std::nullopt, expected, source, false};
  };
  if (!reader_) return pending(Resolution::unavailable, "cell_db_reader_absent");
  if (use == CodeUse::execution && tx.orig_status != schema::active)
    return pending(Resolution::unsupported, "pre_state_not_active_use_applied_init");
  if (use == CodeUse::post_state && tx.end_status != schema::active)
    return pending(Resolution::unsupported, "post_state_not_active");

  try {
    // The parser takes these hashes from this transaction's native HASH_UPDATE.
    // This reader is the ParsedBlock's CellDB snapshot, not a latest-account query.
    auto loaded = reader_->load_cell(expected.as_slice());
    if (loaded.is_error()) return pending(Resolution::unavailable, "cell_db_state_unavailable");
    auto cell = loaded.move_as_ok();
    if (cell.is_null() || td::Bits256(cell->get_hash().bits()) != expected)
      return pending(Resolution::unsupported, "cell_db_state_hash_mismatch");
    if (block::gen::t_Account.get_tag(vm::load_cell_slice(cell)) != block::gen::Account::account)
      return pending(Resolution::unsupported, "cell_db_state_not_account");
    block::gen::Account::Record_account account;
    if (!tlb::unpack_cell(cell, account))
      return pending(Resolution::unsupported, "cell_db_account_malformed");
    block::StdAddress address;
    if (!block::tlb::t_MsgAddressInt.extract_std_address(account.addr, address) || address != tx.account)
      return pending(Resolution::unsupported, "cell_db_account_address_mismatch");
    block::gen::AccountStorage::Record storage;
    if (!tlb::csr_unpack(account.storage, storage))
      return pending(Resolution::unsupported, "cell_db_storage_malformed");
    if (block::gen::t_AccountState.get_tag(storage.state.write()) != block::gen::AccountState::account_active)
      return pending(Resolution::unsupported, "cell_db_account_not_active");
    block::gen::AccountState::Record_account_active active;
    block::gen::StateInit::Record init;
    if (!tlb::csr_unpack(storage.state, active) || !tlb::csr_unpack(active.x, init))
      return pending(Resolution::unsupported, "cell_db_active_state_malformed");
    auto code = init.code;
    if (code.is_null() || code.write().fetch_ulong(1) != 1 || code->size_refs() == 0)
      return pending(Resolution::unsupported, "cell_db_active_code_missing");
    auto code_cell = code->prefetch_ref();
    if (code_cell.is_null()) return pending(Resolution::unsupported, "cell_db_active_code_missing");
    const auto code_hash = td::Bits256(code_cell->get_hash().bits());
    return {Resolution::resolved, code_hash, expected,
            use == CodeUse::execution ? "cell_db_verified_pre_state" : "cell_db_verified_committed_post_state",
            true};
  } catch (const vm::VmError&) {
    return pending(Resolution::unsupported, "cell_db_state_decode_error");
  }
}

CodeFact classify(const CodeEvidence& evidence) {
  CodeFact fact;
  fact.resolution = evidence.resolution;
  fact.source = evidence.source;
  if (!evidence.verified || evidence.resolution != Resolution::resolved || !evidence.code_hash) return fact;
  auto hash = evidence.code_hash->to_hex();
  std::transform(hash.begin(), hash.end(), hash.begin(),
                 [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  fact.code_hash_hex = hash;
  for (auto [known, type] : kRegistry) {
    if (hash == known) {
      fact.wallet_type_id = type;
      fact.classification = Classification::included_wallet;
      return fact;
    }
  }
  for (auto excluded : kExcluded) {
    if (hash == excluded) {
      fact.classification = Classification::excluded_code;
      return fact;
    }
  }
  fact.classification = Classification::outside_registry; // known hash; not a claim about all possible wallets
  return fact;
}

Batch extract_included(const std::vector<schema::Block>& first_included, const BlockId& mc,
                       VerifiedCodeResolver& resolver,
                       const std::vector<schema::AccountState>& states) {
  if (mc.workchain != -1 || mc.root_hash.empty() || mc.file_hash.empty())
    throw std::invalid_argument("Wallets: missing full masterchain anchor");
  Batch batch;
  batch.mc = mc;
  std::set<decltype(coordinate(mc))> block_coordinates;
  std::set<std::tuple<std::string, uint64_t>> tx_keys;
  bool saw_mc = false;
  for (const auto& block : first_included) {
    auto id = id_of(block);
    if (id.root_hash.empty() || id.file_hash.empty() || !block_coordinates.insert(coordinate(id)).second)
      throw std::invalid_argument("Wallets: incomplete or repeated first-included block");
    if (id.workchain == -1) {
      if (id_key(id) != id_key(mc)) throw std::invalid_argument("Wallets: wrong MC block");
      saw_mc = true;
    } else if (block.mc_block_seqno != mc.seqno || block.mc_block_workchain != mc.workchain ||
               block.mc_block_shard != mc.shard) {
      throw std::invalid_argument("Wallets: shard not bound to MC anchor");
    }
    batch.included_blocks.push_back(id);
    for (const auto& tx : block.transactions) {
      auto account = raw_address(tx.account);
      auto hash = tx.hash.to_hex();
      if (tx.account.workchain != id.workchain || tx.mc_seqno != mc.seqno ||
          !tx_keys.insert({account, tx.lt}).second)
        throw std::invalid_argument("Wallets: conflicting or repeated transaction");
      TxId tid{account, tx.lt, hash, tx.now, tx.now - tx.now % 86400, mc, id,
               tx.account_state_hash_before.to_hex(), tx.account_state_hash_after.to_hex()};
      if (tx.orig_status == schema::active || tx.end_status == schema::active) {
        ActiveWitness witness{tid, tx.orig_status, tx.end_status, tx.account_state_hash_after.to_hex(),
                              tx.orig_status == schema::uninit && tx.end_status == schema::active, {}};
        if (tx.end_status == schema::active) {
          witness.post_code = classify(resolve_code(tx, CodeUse::post_state, states, resolver));
          if (witness.post_code.classification == Classification::pending) ++batch.pending_post_codes;
        }
        batch.active_witnesses.push_back(std::move(witness));
      }
      for (const auto& msg : tx.out_msgs) {
        if (!qualifying(msg, account)) continue;
        auto code = classify(resolve_code(tx, CodeUse::execution, states, resolver));
        if (code.classification == Classification::pending) ++batch.pending_execution_codes;
        batch.sends.push_back({tid, msg.hash.to_hex(), std::move(code)});
        break;
      }
    }
  }
  if (!saw_mc) throw std::invalid_argument("Wallets: MC block missing from first-included range");
  return batch;
}

Batch extract(const ParsedBlock& parsed, VerifiedCodeResolver& resolver) {
  std::set<std::tuple<int32_t, int64_t, uint32_t, std::string, std::string>> included;
  std::optional<BlockId> mc;
  for (const auto& entry : parsed.mc_block_.shard_blocks_diff_) {
    if (entry.block_data.is_null()) throw std::invalid_argument("Wallets: null diff block");
    auto id = entry.block_data->block_id();
    BlockId b{id.id.workchain, static_cast<int64_t>(id.id.shard), id.id.seqno,
              td::base64_encode(id.root_hash.as_slice()), td::base64_encode(id.file_hash.as_slice())};
    if (!included.insert(id_key(b)).second) throw std::invalid_argument("Wallets: repeated diff block");
    if (b.workchain == -1) {
      if (mc) throw std::invalid_argument("Wallets: multiple diff masterchain blocks");
      mc = std::move(b);
    }
  }
  if (!mc || parsed.blocks_.size() != included.size())
    throw std::invalid_argument("Wallets: parsed blocks do not cover diff exactly");
  for (const auto& b : parsed.blocks_) {
    if (!included.erase(id_key(id_of(b)))) throw std::invalid_argument("Wallets: parsed block not in diff");
  }
  return extract_included(parsed.blocks_, *mc, resolver, parsed.account_states_);
}

Batch extract(const ParsedBlock& parsed) {
  CellDbVerifiedResolver resolver(parsed.cell_db_reader_);
  return extract(parsed, resolver);
}

} // namespace ton_analytics::wallets::events
