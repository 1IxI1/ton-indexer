#include "ValidatorSnapshot.h"

#include "crypto/block/block-auto.h"
#include "crypto/block/block-parse.h"
#include "crypto/block/block.h"
#include "crypto/block/mc-config.h"
#include "crypto/vm/dict.h"

#include <algorithm>
#include <limits>
#include <set>
#include <stdexcept>

namespace analytics::validators {
namespace {

void fail(Metric &metric, Readiness status, std::string reason) {
  metric.status = status;
  metric.reason = std::move(reason);
  metric.value.reset();
}

using Amount = unsigned __int128;
constexpr Amount kMaxAmount = static_cast<Amount>(-1);

Amount parse_amount(const std::string &text) {
  if (text.empty())
    throw std::runtime_error("empty_amount");
  Amount out = 0;
  for (char c : text) {
    if (c < '0' || c > '9' || out > (kMaxAmount - (c - '0')) / 10)
      throw std::runtime_error("amount_invalid_or_overflow");
    out = out * 10 + (c - '0');
  }
  return out;
}

std::string decimal(Amount n) {
  std::string out;
  do {
    out.push_back('0' + n % 10);
    n /= 10;
  } while (n);
  std::reverse(out.begin(), out.end());
  return out;
}

void add_checked(Amount &total, Amount value) {
  if (value > kMaxAmount - total)
    throw std::runtime_error("sum_overflow");
  total += value;
}

std::string grams(vm::CellSlice &cs) {
  auto v = block::tlb::t_Grams.as_integer_skip(cs);
  if (v.is_null())
    throw std::runtime_error("invalid_grams");
  auto text = v->to_dec_string();
  parse_amount(text);
  return text;
}

td::Ref<vm::Cell> config_cell(const block::ConfigInfo &config, int slot,
                              std::optional<td::Bits256> &hash) {
  auto cell = config.get_config_param(slot);
  if (cell.not_null())
    hash = cell->get_hash().bits();
  return cell;
}

const td::Bits256 &reviewed_elector_hash() {
  static const td::Bits256 hash = [] {
    td::Bits256 parsed;
    if (parsed.from_hex(td::Slice(kReviewedElectorCodeHash.data(),
                                  kReviewedElectorCodeHash.size())) != 256)
      throw std::logic_error("invalid_pinned_elector_code_hash");
    return parsed;
  }();
  return hash;
}

void decode_roster(Snapshot &out, td::Ref<vm::Cell> root) {
  // Decode the Hashmap keys, rather than assigning indices by iteration order
  // from Config::unpack_validator_set. Cross-check that native decoder accepts
  // it.
  auto native = block::Config::unpack_validator_set(root);
  if (native.is_error())
    throw std::runtime_error("native_validator_set_invalid");
  block::gen::ValidatorSet::Record_validators_ext ext;
  td::Ref<vm::Cell> dict_root;
  if (tlb::unpack_cell(root, ext)) {
    out.utime_since = ext.utime_since;
    out.utime_until = ext.utime_until;
    out.total = static_cast<uint16_t>(ext.total);
    out.main = static_cast<uint16_t>(ext.main);
    out.total_weight = ext.total_weight;
    dict_root = ext.list->prefetch_ref();
  } else {
    block::gen::ValidatorSet::Record_validators legacy;
    if (!tlb::unpack_cell(root, legacy))
      throw std::runtime_error("validator_set_layout_invalid");
    out.utime_since = legacy.utime_since;
    out.utime_until = legacy.utime_until;
    out.total = static_cast<uint16_t>(legacy.total);
    out.main = static_cast<uint16_t>(legacy.main);
    out.total_weight = native.ok()->total_weight;
    dict_root = vm::Dictionary::construct_root_from(*legacy.list);
  }
  if (!out.total || out.main > out.total || out.utime_since >= out.utime_until)
    throw std::runtime_error("validator_set_header_invalid");
  vm::Dictionary dict{dict_root, 16};
  for (auto it = dict.begin(); !it.eof(); ++it) {
    Member member;
    member.index =
        static_cast<uint16_t>(td::BitArray<16>(it.cur_pos()).to_ulong());
    auto value = *it.cur_value();
    block::gen::ValidatorDescr::Record_validator_addr extended;
    td::Ref<vm::CellSlice> key_slice;
    if (block::gen::t_ValidatorDescr.unpack(value, extended) &&
        value.empty_ext()) {
      key_slice = extended.public_key;
      member.weight = extended.weight;
      member.adnl = extended.adnl_addr;
    } else {
      value = *it.cur_value();
      block::gen::ValidatorDescr::Record_validator older;
      if (!block::gen::t_ValidatorDescr.unpack(value, older) ||
          !value.empty_ext())
        throw std::runtime_error("validator_descriptor_invalid");
      key_slice = older.public_key;
      member.weight = older.weight;
    }
    block::gen::SigPubKey::Record pk;
    if (!tlb::csr_unpack(key_slice, pk))
      throw std::runtime_error("validator_pubkey_invalid");
    member.pubkey = pk.pubkey;
    out.members.push_back(member);
    if (out.members.size() > 65535)
      throw std::runtime_error("validator_set_unbounded");
  }
  validate_roster(out);
  if (out.count.status != Readiness::ready)
    throw std::runtime_error(out.count.reason);
  if (native.ok()->total_weight != out.total_weight ||
      native.ok()->list.size() != out.members.size())
    throw std::runtime_error("native_validator_set_mismatch");
}

void decode_elector(Snapshot &out, const td::Ref<vm::Cell> &state_root,
                    const block::ConfigInfo &config, const Input &input) {
  std::optional<td::Bits256> config1_hash;
  auto elector_config = config_cell(config, 1, config1_hash);
  if (elector_config.is_null()) {
    fail(out.frozen_remaining, Readiness::pending, "missing_config_1");
    return;
  }
  auto addr_cs = vm::load_cell_slice(elector_config);
  td::Bits256 addr;
  if (!addr_cs.fetch_bits_to(addr) || !addr_cs.empty_ext())
    throw std::runtime_error("malformed_config_1");
  out.elector_address = addr;
  block::gen::ShardStateUnsplit::Record shard;
  if (!tlb::unpack_cell(state_root, shard))
    throw std::runtime_error("invalid_mc_shard_state");
  vm::AugmentedDictionary accounts{vm::load_cell_slice_ref(shard.accounts), 256,
                                   block::tlb::aug_ShardAccounts};
  auto record = accounts.lookup(addr);
  if (record.is_null()) {
    fail(out.frozen_remaining, Readiness::pending, "missing_elector_account");
    return;
  }
  block::gen::ShardAccount::Record shard_account;
  if (!tlb::csr_unpack(std::move(record), shard_account) ||
      shard_account.account.is_null())
    throw std::runtime_error("malformed_elector_shard_account");
  out.elector_account_hash = shard_account.account->get_hash().bits();
  block::gen::Account::Record_account account;
  if (!tlb::unpack_cell(shard_account.account, account))
    throw std::runtime_error("elector_account_not_active");
  ton::WorkchainId wc;
  ton::StdSmcAddress account_addr;
  if (!block::tlb::t_MsgAddressInt.extract_std_address(account.addr, wc,
                                                       account_addr) ||
      wc != -1 || account_addr != addr)
    throw std::runtime_error("elector_account_address_mismatch");
  block::gen::AccountStorage::Record storage;
  block::gen::AccountState::Record_account_active active;
  block::gen::StateInit::Record init;
  if (!tlb::csr_unpack(account.storage, storage) ||
      !tlb::csr_unpack(storage.state, active) ||
      !tlb::csr_unpack(active.x, init))
    throw std::runtime_error("elector_state_not_active");
  auto code_slice = *init.code;
  auto data_slice = *init.data;
  if (code_slice.fetch_ulong(1) != 1 || data_slice.fetch_ulong(1) != 1)
    throw std::runtime_error("elector_code_or_data_missing");
  auto code = code_slice.prefetch_ref();
  auto data = data_slice.prefetch_ref();
  if (code.is_null() || data.is_null())
    throw std::runtime_error("elector_code_or_data_missing");
  decode_elector_data_cell(out, data, td::Bits256(code->get_hash().bits()),
                           input.supported_elector_code_hashes);
}

void decode_elector_data_unchecked(Snapshot &out,
                                   const td::Ref<vm::Cell> &data) {
  auto ds = vm::load_cell_slice(data);
  td::Ref<vm::Cell> current, credits, past;
  if (!ds.fetch_maybe_ref(current) || !ds.fetch_maybe_ref(credits) ||
      !ds.fetch_maybe_ref(past))
    throw std::runtime_error("elector_data_layout_invalid");
  grams(ds);          // reserve; not stake
  ds.fetch_ulong(32); // active_id
  td::Bits256 active_hash;
  if (!ds.fetch_bits_to(active_hash) || !ds.empty_ext())
    throw std::runtime_error("elector_data_trailing_fields");
  if (past.is_null()) {
    fail(out.frozen_remaining, Readiness::pending, "past_elections_missing");
    return;
  }
  out.past_elections_root_hash = past->get_hash().bits();
  vm::Dictionary elections{past, 32};
  unsigned matches = 0, scanned = 0;
  for (auto it = elections.begin(); !it.eof(); ++it) {
    if (++scanned > 4096)
      throw std::runtime_error("past_elections_limit_exceeded");
    auto value = *it.cur_value();
    auto unfreeze_at = value.fetch_ulong(32);
    auto held = value.fetch_ulong(32);
    td::Bits256 hash;
    td::Ref<vm::Cell> frozen, complaints;
    if (!value.fetch_bits_to(hash) || !value.fetch_maybe_ref(frozen))
      throw std::runtime_error("past_election_header_invalid");
    auto total = grams(value);
    grams(value); // bonus, not remaining frozen principal
    if (!value.fetch_maybe_ref(complaints) || !value.empty_ext())
      throw std::runtime_error("past_election_trailing_fields");
    if (hash != *out.config34_hash)
      continue;
    if (++matches != 1)
      throw std::runtime_error("ambiguous_election_vset_hash");
    out.election_id = td::BitArray<32>(it.cur_pos()).to_ulong();
    out.unfreeze_at = unfreeze_at;
    out.stake_held_for = held;
    out.matched_vset_hash = hash;
    out.frozen_declared_total_nanoton = total;
    if (frozen.not_null()) {
      out.frozen_root_hash = frozen->get_hash().bits();
      vm::Dictionary dict{frozen, 256};
      for (auto f = dict.begin(); !f.eof(); ++f) {
        FrozenMember member;
        member.pubkey = td::BitArray<256>(f.cur_pos());
        auto fs = *f.cur_value();
        unsigned long long weight;
        if (!fs.fetch_bits_to(member.raw_holder) ||
            !fs.fetch_uint_to(64, weight))
          throw std::runtime_error("frozen_holder_or_weight_invalid");
        member.weight = weight;
        member.stake_nanoton = grams(fs);
        if (fs.size() != 1 || fs.size_refs() != 0)
          throw std::runtime_error("frozen_banned_flag_invalid");
        member.banned = fs.fetch_ulong(1);
        out.frozen.push_back(member);
        if (out.frozen.size() > out.members.size())
          throw std::runtime_error("frozen_member_extra");
      }
    }
  }
  if (!matches) {
    fail(out.frozen_remaining, Readiness::pending,
         "election_vset_hash_not_matched");
    return;
  }
  validate_frozen(out, *out.frozen_declared_total_nanoton);
}

} // namespace

bool valid_network_zerostate(std::string_view hash_hex) {
  if (hash_hex.size() != 64)
    return false;
  bool nonzero = false;
  for (char c : hash_hex) {
    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
          (c >= 'A' && c <= 'F')))
      return false;
    nonzero |= c != '0';
  }
  return nonzero;
}

bool elector_code_enabled_for_decoder(
    const td::Bits256 &code_hash,
    const std::vector<td::Bits256> &caller_allowlist) {
  return code_hash == reviewed_elector_hash() &&
         std::find(caller_allowlist.begin(), caller_allowlist.end(),
                   code_hash) != caller_allowlist.end();
}

void decode_validator_set_cell(Snapshot &out,
                               const td::Ref<vm::Cell> &config34) {
  fail(out.count, Readiness::pending, "config_34_not_decoded");
  fail(out.frozen_remaining, Readiness::pending, "count_not_ready");
  out.members.clear();
  out.frozen.clear();
  out.config34_hash.reset();
  out.elector_address.reset();
  out.elector_account_hash.reset();
  out.elector_code_hash.reset();
  out.elector_data_hash.reset();
  out.election_id.reset();
  out.unfreeze_at.reset();
  out.stake_held_for.reset();
  out.matched_vset_hash.reset();
  out.frozen_declared_total_nanoton.reset();
  out.past_elections_root_hash.reset();
  out.frozen_root_hash.reset();
  out.utime_since = out.utime_until = 0;
  out.total = out.main = 0;
  out.total_weight = 0;
  if (config34.is_null()) {
    fail(out.count, Readiness::pending, "missing_config_34");
    return;
  }
  try {
    out.config34_hash = config34->get_hash().bits();
    decode_roster(out, config34);
  } catch (const vm::VmError &e) {
    fail(out.count, Readiness::pending,
         std::string("validator_cell_unavailable: ") + e.get_msg());
    out.members.clear();
  } catch (const std::exception &e) {
    fail(out.count, Readiness::invalid, e.what());
    out.members.clear();
  }
}

void decode_elector_data_cell(
    Snapshot &out, const td::Ref<vm::Cell> &elector_data,
    const td::Bits256 &elector_code_hash,
    const std::vector<td::Bits256> &caller_allowlist) {
  fail(out.frozen_remaining, Readiness::pending, "elector_data_not_verified");
  out.frozen.clear();
  out.elector_code_hash.reset();
  out.elector_data_hash.reset();
  out.election_id.reset();
  out.unfreeze_at.reset();
  out.stake_held_for.reset();
  out.matched_vset_hash.reset();
  out.frozen_declared_total_nanoton.reset();
  out.past_elections_root_hash.reset();
  out.frozen_root_hash.reset();
  if (out.count.status != Readiness::ready || !out.config34_hash) {
    fail(out.frozen_remaining, Readiness::pending, "count_not_ready");
    return;
  }
  out.elector_code_hash = elector_code_hash;
  if (elector_data.is_null()) {
    fail(out.frozen_remaining, Readiness::pending, "missing_elector_data");
    return;
  }
  try {
    out.elector_data_hash = elector_data->get_hash().bits();
    if (elector_code_hash != reviewed_elector_hash()) {
      fail(out.frozen_remaining, Readiness::pending,
           "elector_code_hash_not_reviewed");
      return;
    }
    if (!elector_code_enabled_for_decoder(elector_code_hash,
                                          caller_allowlist)) {
      fail(out.frozen_remaining, Readiness::pending,
           "elector_code_not_enabled_by_caller");
      return;
    }
    decode_elector_data_unchecked(out, elector_data);
  } catch (const vm::VmError &e) {
    fail(out.frozen_remaining, Readiness::pending,
         std::string("elector_cell_unavailable: ") + e.get_msg());
    out.frozen.clear();
  } catch (const std::exception &e) {
    fail(out.frozen_remaining, Readiness::invalid, e.what());
    out.frozen.clear();
  }
}

void validate_roster(Snapshot &out) {
  std::string reason;
  std::set<uint16_t> indices;
  std::set<td::Bits256> keys;
  uint64_t sum = 0;
  if (!out.total || !out.main || out.main > out.total ||
      out.utime_since >= out.utime_until)
    reason = "validator_set_header_invalid";
  if (out.members.size() != out.total && reason.empty())
    reason = "validator_set_count_mismatch";
  for (const auto &m : out.members) {
    if ((m.index >= out.total || !indices.insert(m.index).second) &&
        reason.empty())
      reason = "validator_index_invalid_or_duplicate";
    if (!keys.insert(m.pubkey).second && reason.empty())
      reason = "validator_pubkey_duplicate";
    if (!m.weight && reason.empty())
      reason = "validator_weight_zero";
    if (m.weight > std::numeric_limits<uint64_t>::max() - sum) {
      if (reason.empty())
        reason = "validator_total_weight_overflow";
    } else {
      sum += m.weight;
    }
  }
  if ((indices.size() != out.total || sum != out.total_weight || !sum) &&
      reason.empty())
    reason = "validator_total_weight_or_indices_mismatch";
  if (!reason.empty()) {
    fail(out.count, Readiness::invalid, reason);
    out.members.clear();
    return;
  }
  out.count = {Readiness::ready, "", std::to_string(out.total)};
}

void validate_frozen(Snapshot &out, const std::string &declared_total_nanoton) {
  fail(out.frozen_remaining, Readiness::invalid, "frozen_not_verified");
  try {
    if (out.count.status != Readiness::ready || !out.config34_hash ||
        !out.matched_vset_hash || *out.config34_hash != *out.matched_vset_hash)
      throw std::runtime_error("election_vset_hash_not_matched");
    if (out.frozen.size() != out.members.size())
      throw std::runtime_error("frozen_member_missing_or_extra");
    std::map<td::Bits256, uint64_t> expected;
    for (const auto &m : out.members)
      expected.emplace(m.pubkey, m.weight);
    std::set<td::Bits256> seen;
    Amount total = 0;
    for (const auto &f : out.frozen) {
      auto it = expected.find(f.pubkey);
      if (it == expected.end() || !seen.insert(f.pubkey).second)
        throw std::runtime_error("frozen_member_missing_or_extra");
      if (f.weight != it->second)
        throw std::runtime_error("frozen_weight_mismatch");
      add_checked(total, parse_amount(f.stake_nanoton));
    }
    if (total != parse_amount(declared_total_nanoton))
      throw std::runtime_error("stake_sum_mismatch");
    out.frozen_remaining = {Readiness::ready, "", decimal(total)};
  } catch (const std::exception &e) {
    fail(out.frozen_remaining, Readiness::invalid, e.what());
    out.frozen.clear();
  }
}

td::Result<Snapshot>
extract_validator_snapshot(const schema::MasterchainBlockDataState &loaded,
                           const Input &input) {
  Snapshot out;
  out.network_zerostate = input.network_zerostate;
  out.mc_id = input.expected_mc_id;
  out.state_hash = input.expected_state_hash;
  out.state_update_verified = input.state_update_verified;
  fail(out.count, Readiness::pending, "missing_mc_state");
  fail(out.frozen_remaining, Readiness::pending, "count_not_ready");
  if (!valid_network_zerostate(input.network_zerostate)) {
    fail(out.count, Readiness::pending, "invalid_network_zerostate");
    return out;
  }
  if (!input.expected_mc_id.is_masterchain() ||
      !input.expected_mc_id.is_valid() || !input.state_update_verified) {
    fail(out.count, Readiness::pending, "unverified_mc_post_state_identity");
    return out;
  }
  try {
    if (loaded.shard_blocks_.empty())
      return out;
    const auto &tip = loaded.shard_blocks_.front();
    if (!tip.handle || tip.block_data.is_null() || tip.block_state.is_null())
      return out;
    if (tip.handle->id() != input.expected_mc_id ||
        tip.block_data->block_id() != input.expected_mc_id ||
        td::Bits256(tip.block_state->get_hash().bits()) !=
            input.expected_state_hash) {
      fail(out.count, Readiness::invalid, "mc_id_or_state_hash_mismatch");
      return out;
    }
    block::gen::Block::Record block;
    block::gen::BlockInfo::Record info;
    auto block_root = tip.block_data->root_cell();
    if (block_root.is_null() ||
        td::Bits256(block_root->get_hash().bits()) !=
            input.expected_mc_id.root_hash ||
        !tlb::unpack_cell(block_root, block) ||
        !tlb::unpack_cell(block.info, info))
      throw std::runtime_error("mc_block_info_invalid");
    out.gen_utime = info.gen_utime;
    block::gen::ShardStateUnsplit::Record mc_state;
    if (!tlb::unpack_cell(tip.block_state, mc_state) ||
        mc_state.gen_utime != out.gen_utime)
      throw std::runtime_error("mc_state_time_or_layout_mismatch");
    auto result =
        block::ConfigInfo::extract_config(tip.block_state, input.expected_mc_id,
                                          block::ConfigInfo::needCapabilities);
    if (result.is_error())
      throw std::runtime_error("mc_post_state_config_invalid");
    auto config = result.move_as_ok();
    config_cell(*config, 32, out.config32_hash);
    config_cell(*config, 35, out.config35_hash);
    config_cell(*config, 36, out.config36_hash);
    auto set = config_cell(*config, 34, out.config34_hash);
    if (set.is_null()) {
      fail(out.count, Readiness::pending, "missing_config_34");
      return out;
    }
    decode_validator_set_cell(out, set);
    if (out.count.status != Readiness::ready)
      return out;
    if (!(out.utime_since <= out.gen_utime &&
          out.gen_utime < out.utime_until)) {
      fail(out.count, Readiness::invalid, "config_34_outside_anchor_epoch");
      out.members.clear();
      return out;
    }
    fail(out.frozen_remaining, Readiness::pending, "elector_not_loaded");
    try {
      decode_elector(out, tip.block_state, *config, input);
    } catch (const vm::VmError &e) {
      // The reader decides whether a cell is pruned or failed to load; never
      // turn either condition into a proved-absent account or a zero stake.
      fail(out.frozen_remaining, Readiness::pending,
           std::string("elector_cell_unavailable: ") + e.get_msg());
      out.frozen.clear();
    } catch (const std::exception &e) {
      fail(out.frozen_remaining, Readiness::invalid, e.what());
      out.frozen.clear();
    }
  } catch (const vm::VmError &e) {
    fail(out.count, Readiness::pending,
         std::string("mc_cell_unavailable: ") + e.get_msg());
    out.members.clear();
  } catch (const std::exception &e) {
    fail(out.count, Readiness::invalid, e.what());
    out.members.clear();
  }
  if (out.count.status != Readiness::ready) {
    fail(out.frozen_remaining, Readiness::pending, "count_not_ready");
    out.frozen.clear();
  }
  return out;
}

} // namespace analytics::validators
