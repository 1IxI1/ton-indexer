#include "Extractor.h"

#include "block/block-auto.h"
#include "block/block-parse.h"
#include "smc-envelope/SmartContract.h"
#include "td/utils/crypto.h"
#include "td/utils/misc.h"
#include "vm/dict.h"
#include "vm/stack.hpp"

#include <algorithm>
#include <charconv>
#include <limits>
#include <string>
#include <utility>

namespace assets_analytics {
namespace {

std::string hex(td::Bits256 hash) { return hash.to_hex(); }
std::string address_string(const block::StdAddress& address) {
  return std::to_string(address.workchain) + ":" + address.addr.to_hex();
}

// Do not silently normalize anycast or accept variable-length addresses.
td::Result<block::StdAddress> std_address(td::Ref<vm::CellSlice> slice) {
  if (slice.is_null() || block::gen::t_MsgAddressInt.get_tag(*slice) != block::gen::MsgAddressInt::addr_std) {
    return td::Status::Error("not a standard internal address");
  }
  block::gen::MsgAddressInt::Record_addr_std decoded;
  if (!tlb::csr_unpack(slice, decoded) ||
      (decoded.anycast.not_null() && decoded.anycast->prefetch_ulong(1) != 0)) {
    return td::Status::Error("invalid or anycast address");
  }
  return block::StdAddress(decoded.workchain_id, decoded.address);
}

struct Loaded {
  AccountEvidence evidence;
  td::Ref<vm::Cell> code;
  td::Ref<vm::Cell> data;
  td::uint64 balance{0};
  td::Ref<vm::Cell> extra;
  const StateRoot* source{nullptr};
};

Loaded lookup(const Anchor& anchor, const block::StdAddress& address) {
  Loaded out;
  out.evidence.address = address_string(address);
  const StateRoot* selected = nullptr;
  block::gen::ShardStateUnsplit::Record state;
  // An incomplete or ambiguous manifest must not yield a proved absence.
  if (!anchor.caller_attests_complete_tip_manifest) return out;
  auto find_in = [&](const StateRoot& candidate) {
    if (candidate.root.is_null() || !candidate.caller_attests_state_update_verified) return false;
    td::Bits256 actual_hash;
    actual_hash = candidate.root->get_hash().bits();
    if (actual_hash != candidate.state_root_hash) return false;
    block::gen::ShardStateUnsplit::Record parsed;
    if (!tlb::unpack_cell(candidate.root, parsed)) return false;
    if (!(block::ShardId(parsed.shard_id) == block::ShardId(candidate.block_id))) return false;
    if (!ton::shard_contains(ton::ShardIdFull(block::ShardId(parsed.shard_id)),
                             ton::extract_addr_prefix(address.workchain, address.addr))) return false;
    if (selected) {
      out.evidence.lookup = AccountLookup::error;
      return true;
    }
    selected = &candidate;
    state = std::move(parsed);
    return false;
  };
  if (address.workchain == ton::masterchainId) {
    find_in(anchor.mc);
  } else {
    for (const auto& tip : anchor.shard_tips) {
      if (find_in(tip)) return out;
    }
  }
  if (!selected) return out;
  out.source = selected;
  vm::AugmentedDictionary accounts(vm::load_cell_slice_ref(state.accounts), 256, block::tlb::aug_ShardAccounts);
  auto entry = accounts.lookup(address.addr);
  if (entry.is_null()) {
    out.evidence.lookup = AccountLookup::not_present;
    return out;
  }
  block::gen::ShardAccount::Record shard_account;
  if (!tlb::csr_unpack(std::move(entry), shard_account) || shard_account.account.is_null()) {
    out.evidence.lookup = AccountLookup::error;
    return out;
  }
  auto account_cell = shard_account.account;
  auto account_tag = block::gen::t_Account.get_tag(vm::load_cell_slice(account_cell));
  if (account_tag == block::gen::Account::account_none) {
    out.evidence.lookup = AccountLookup::not_present;
    return out;
  }
  if (account_tag != block::gen::Account::account) {
    out.evidence.lookup = AccountLookup::error;
    return out;
  }
  block::gen::Account::Record_account account;
  block::gen::AccountStorage::Record storage;
  if (!tlb::unpack_cell(account_cell, account) || !tlb::csr_unpack(account.storage, storage)) {
    out.evidence.lookup = AccountLookup::error;
    return out;
  }
  auto parsed_addr = std_address(account.addr);
  if (parsed_addr.is_error() || parsed_addr.ok() != address) {
    out.evidence.lookup = AccountLookup::error;
    return out;
  }
  out.evidence.state_hash = hex(account_cell->get_hash().bits());
  td::RefInt256 grams;
  if (!block::unpack_CurrencyCollection(storage.balance, grams, out.extra) || grams.is_null() ||
      grams->sgn() < 0) {
    out.evidence.lookup = AccountLookup::error;
    return out;
  }
  out.evidence.ton_balance_nanoton = grams->to_dec_string();
  if (out.extra.not_null()) out.evidence.extra_currencies_hash = hex(out.extra->get_hash().bits());
  // SmartContract::Args only exposes uint64 TON balance; never truncate larger balances.
  if (!grams->unsigned_fits_bits(64)) {
    out.evidence.lookup = AccountLookup::unknown;
    return out;
  }
  auto text = out.evidence.ton_balance_nanoton;
  auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), out.balance);
  if (error != std::errc{} || end != text.data() + text.size()) {
    out.evidence.lookup = AccountLookup::unknown;
    return out;
  }
  auto tag = block::gen::t_AccountState.get_tag(storage.state.write());
  if (tag == block::gen::AccountState::account_uninit) {
    out.evidence.account_status = "uninit";
  } else if (tag == block::gen::AccountState::account_frozen) {
    out.evidence.account_status = "frozen";
  } else if (tag == block::gen::AccountState::account_active) {
    out.evidence.account_status = "active";
    block::gen::AccountState::Record_account_active active;
    block::gen::StateInit::Record state_init;
    if (!tlb::csr_unpack(storage.state, active) || !tlb::csr_unpack(active.x, state_init)) {
      out.evidence.lookup = AccountLookup::error;
      return out;
    }
    auto& code = state_init.code.write();
    auto& data = state_init.data.write();
    if (code.fetch_long(1) != 0) out.code = code.prefetch_ref();
    if (data.fetch_long(1) != 0) out.data = data.prefetch_ref();
    if (out.code.not_null()) out.evidence.code_hash = hex(out.code->get_hash().bits());
    if (out.data.not_null()) out.evidence.data_hash = hex(out.data->get_hash().bits());
  } else {
    out.evidence.lookup = AccountLookup::error;
    return out;
  }
  out.evidence.lookup = AccountLookup::found;
  return out;
}

td::Result<std::vector<vm::StackEntry>> run_get(const Anchor& anchor, const Loaded& account,
                                                  const block::StdAddress& address, const char* method,
                                                  std::vector<vm::StackEntry> stack) {
  if (!anchor.config || !anchor.caller_attests_config_from_this_mc_root ||
      account.code.is_null() || account.data.is_null()) {
    return td::Status::Error("missing historical code/data/config");
  }
  ton::SmartContract smc({account.code, account.data});
  ton::SmartContract::Args args;
  args.set_now(static_cast<int>(anchor.gen_utime));
  args.set_address(address);
  args.set_balance(account.balance);
  args.set_extra_currencies(account.extra);
  args.set_config(anchor.config);
  args.set_libraries(vm::Dictionary(anchor.config->get_libraries_root(), 256));
  args.set_method_id(td::Slice(method));
  args.set_stack(std::move(stack));
  auto result = smc.run_get_method(std::move(args));
  if (!result.success || result.stack.is_null()) return td::Status::Error("historical getter failed");
  return result.stack->extract_contents();
}

bool valid(const StateRoot& root) {
  if (root.root.is_null() || !root.caller_attests_state_update_verified) return false;
  td::Bits256 actual_hash;
  actual_hash = root.root->get_hash().bits();
  return actual_hash == root.state_root_hash;
}

}  // namespace

td::Result<std::vector<Observation>> observe_wallets(const Anchor& anchor,
                                                       const std::vector<block::StdAddress>& wallets,
                                                       Budget budget) {
  if (!budget.max_wallets || wallets.size() > budget.max_wallets ||
      anchor.getter_context_audits.size() > budget.max_wallets)
    return td::Status::Error("wallet/audit limit exceeded");
  if (!budget.max_tip_roots || anchor.shard_tips.empty() ||
      anchor.shard_tips.size() > budget.max_tip_roots || !budget.max_total_provenance_bytes)
    return td::Status::Error("tip manifest limit exceeded");
  if (anchor.network.size() > 256 || anchor.zerostate.size() > 256)
    return td::Status::Error("anchor identity byte limit exceeded");
  size_t audit_input_bytes = 0;
  for (const auto& audit : anchor.getter_context_audits) {
    if (audit.current_shard_tips.size() > budget.max_tip_roots)
      return td::Status::Error("audit tip limit exceeded");
    const std::string* fields[] = {
        &audit.report_id, &audit.report_sha256, &audit.allowlist_policy_version,
        &audit.c7_dependency_assessment, &audit.wallet_address, &audit.wallet_state_hash,
        &audit.wallet_code_hash, &audit.master_address, &audit.master_state_hash,
        &audit.master_code_hash, &audit.mc_block_id, &audit.mc_state_root_hash,
        &audit.tip_manifest_sha256, &audit.config_hash, &audit.wallet_method,
        &audit.master_method, &audit.audited_vm_context_limits};
    for (const auto* field : fields) {
      if (field->size() > 512 || field->size() > budget.max_total_provenance_bytes - audit_input_bytes)
        return td::Status::Error("audit input byte limit exceeded");
      audit_input_bytes += field->size();
    }
    for (const auto& tip : audit.current_shard_tips) {
      for (const auto* field : {&tip.block_id, &tip.state_root_hash}) {
        if (field->size() > 512 || field->size() > budget.max_total_provenance_bytes - audit_input_bytes)
          return td::Status::Error("audit manifest byte limit exceeded");
        audit_input_bytes += field->size();
      }
    }
  }
  // Materialize only full identifiers and hashes, never root-cell bytes. Sort for
  // reproducible provenance regardless of caller's tip iteration order.
  std::vector<TipSource> tips;
  tips.reserve(anchor.shard_tips.size());
  size_t manifest_bytes = 0;
  for (const auto& tip : anchor.shard_tips) {
    TipSource item{tip.block_id.to_str(), hex(tip.state_root_hash)};
    if (item.block_id.size() > 512 || item.state_root_hash.size() > 512)
      return td::Status::Error("tip identifier byte limit exceeded");
    size_t bytes = sizeof(TipSource) + item.block_id.size() + item.state_root_hash.size() + 32;
    if (bytes > budget.max_total_provenance_bytes - manifest_bytes)
      return td::Status::Error("tip manifest byte limit exceeded");
    manifest_bytes += bytes;
    tips.push_back(std::move(item));
  }
  if (!fits_aggregate_provenance_budget(audit_input_bytes, manifest_bytes,
                                        wallets.size(), budget.max_total_provenance_bytes))
    return td::Status::Error("audit + aggregate provenance byte limit exceeded");
  std::sort(tips.begin(), tips.end(), [](const TipSource& a, const TipSource& b) {
    return a.block_id < b.block_id || (a.block_id == b.block_id && a.state_root_hash < b.state_root_hash);
  });
  std::string canonical = canonical_tip_manifest(tips);
  auto manifest_digest = td::hex_encode(td::Slice(td::sha256(td::Slice(canonical))));
  std::vector<Observation> results;
  results.reserve(wallets.size());
  for (const auto& address : wallets) {
    Observation o;
    o.wallet.address = address_string(address);
    o.source.network = anchor.network;
    o.source.zerostate = anchor.zerostate;
    o.source.mc_block_id = anchor.mc.block_id.to_str();
    o.source.mc_state_root_hash = hex(anchor.mc.state_root_hash);
    o.source.historical_now = anchor.gen_utime;
    o.source.current_shard_tips = tips;
    o.source.tip_manifest_sha256 = manifest_digest;
    o.source.caller_attests_manifest_complete = anchor.caller_attests_complete_tip_manifest;
    o.source.caller_attests_config_from_mc = anchor.caller_attests_config_from_this_mc_root;
    try {
    bool tips_valid = !anchor.shard_tips.empty();
    for (const auto& tip : anchor.shard_tips) {
      tips_valid = tips_valid && valid(tip);
      block::gen::ShardStateUnsplit::Record state;
      tips_valid = tips_valid && tlb::unpack_cell(tip.root, state) &&
                   block::ShardId(state.shard_id) == block::ShardId(tip.block_id);
    }
    block::gen::ShardStateUnsplit::Record mc_state;
    if (!anchor.mc.block_id.is_masterchain() || !valid(anchor.mc) ||
        !tlb::unpack_cell(anchor.mc.root, mc_state) || mc_state.gen_utime != anchor.gen_utime ||
        !(block::ShardId(mc_state.shard_id) == block::ShardId(anchor.mc.block_id)) ||
        !tips_valid || !anchor.caller_attests_complete_tip_manifest || !anchor.config ||
        !anchor.caller_attests_config_from_this_mc_root || anchor.network.empty() || anchor.zerostate.empty() ||
        !anchor.gen_utime || anchor.gen_utime > static_cast<unsigned>(std::numeric_limits<int>::max()) ||
        !anchor.config->get_root_cell().not_null()) {
      o.reason = "unverified or incomplete MC anchor/config/tip manifest";
      results.push_back(std::move(o));
      continue;
    }
    o.source.config_hash = hex(anchor.config->get_root_cell()->get_hash().bits());
    o.source.caller_attests_state_updates = true;
    auto wallet = lookup(anchor, address);
    o.wallet = wallet.evidence;
    if (wallet.source) {
      o.source.tip_block_id = wallet.source->block_id.to_str();
      o.source.tip_state_root_hash = hex(wallet.source->state_root_hash);
    }
    if (wallet.evidence.lookup != AccountLookup::found || wallet.evidence.account_status != "active" ||
        wallet.code.is_null() || wallet.data.is_null()) {
      o.reason = "wallet absent, inactive or incomplete";
      o.status = classify(o);
      results.push_back(std::move(o));
      continue;
    }
    auto data_r = run_get(anchor, wallet, address, "get_wallet_data", {});
    if (data_r.is_error()) {
      o.reason = "get_wallet_data failed";
      o.status = Status::error;
      results.push_back(std::move(o));
      continue;
    }
    auto data = data_r.move_as_ok();
    if (data.size() != 4 || data[0].type() != vm::StackEntry::Type::t_int ||
        data[1].type() != vm::StackEntry::Type::t_slice ||
        data[2].type() != vm::StackEntry::Type::t_slice ||
        data[3].type() != vm::StackEntry::Type::t_cell || data[3].as_cell().is_null() ||
        data[0].as_int().is_null()) {
      o.reason = "malformed wallet getter result";
      o.status = Status::error;
      results.push_back(std::move(o));
      continue;
    }
    o.raw_signed_balance = data[0].as_int()->to_dec_string();
    o.getter_wallet_code_hash = hex(data[3].as_cell()->get_hash().bits());
    auto owner_r = std_address(data[1].as_slice());
    auto master_r = std_address(data[2].as_slice());
    if (owner_r.is_error() || master_r.is_error()) {
      o.reason = "invalid owner or master address";
      results.push_back(std::move(o));
      continue;
    }
    auto owner = owner_r.move_as_ok();
    auto master = master_r.move_as_ok();
    o.owner = address_string(owner);
    o.master_address = address_string(master);
    auto master_state = lookup(anchor, master);  // always same anchor, even if wallet unchanged
    o.master = master_state.evidence;
    if (master_state.source) {
      o.source.master_tip_block_id = master_state.source->block_id.to_str();
      o.source.master_tip_state_root_hash = hex(master_state.source->state_root_hash);
    }
    if (master_state.evidence.lookup != AccountLookup::found ||
        master_state.evidence.account_status != "active" || master_state.code.is_null() ||
        master_state.data.is_null()) {
      o.reason = "master absent, inactive or incomplete";
      if (master_state.evidence.lookup == AccountLookup::error) o.status = Status::error;
      results.push_back(std::move(o));
      continue;
    }
    vm::CellBuilder builder;
    vm::CellBuilder anycast;
    anycast.store_bool_bool(false);
    block::gen::t_MsgAddressInt.pack_addr_std(builder, vm::load_cell_slice_ref(anycast.finalize()),
                                                owner.workchain, owner.addr);
    auto owner_cell = builder.finalize();
    auto bound_r = run_get(anchor, master_state, master, "get_wallet_address",
                           {vm::StackEntry(vm::load_cell_slice_ref(owner_cell))});
    if (bound_r.is_error()) {
      o.reason = "master get_wallet_address failed";
      o.status = Status::error;
      results.push_back(std::move(o));
      continue;
    }
    auto bound = bound_r.move_as_ok();
    if (bound.size() != 1 || bound[0].type() != vm::StackEntry::Type::t_slice) {
      o.reason = "malformed master getter result";
      o.status = Status::error;
      results.push_back(std::move(o));
      continue;
    }
    auto returned_r = std_address(bound[0].as_slice());
    if (returned_r.is_error()) {
      o.reason = "invalid master-returned address";
      o.status = Status::error;
      results.push_back(std::move(o));
      continue;
    }
    o.master_returned_wallet = address_string(returned_r.move_as_ok());
    o.binding = (*o.master_returned_wallet == o.wallet.address) ? Binding::matched : Binding::unmatched;
    for (const auto& audit : anchor.getter_context_audits) {
      if (audit.wallet_address == o.wallet.address && audit.master_address == o.master.address) {
        o.context_audit = audit;  // retain even a mismatching report as diagnostic evidence
        break;
      }
    }
    o.status = classify(o);
    if (o.status != Status::found) {
      o.reason = o.binding == Binding::unmatched ? "master returned different wallet" :
                  "getter context audit missing/mismatched or invalid balance";
    }
    results.push_back(std::move(o));
    } catch (const vm::VmError&) {
      o.status = Status::error;
      o.reason = "state cell or TVM read failed";
      results.push_back(std::move(o));
    }
  }
  return results;
}

}  // namespace assets_analytics
