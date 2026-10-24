#include "ValidatorElectionObservation.h"

#include "ValidatorSnapshot.h" // public pinned-code and network predicates only
#include "crypto/block/block-auto.h"
#include "crypto/block/block-parse.h"
#include "crypto/block/block.h"
#include "crypto/block/mc-config.h"
#include "crypto/vm/dict.h"

#include <boost/multiprecision/cpp_int.hpp>
#include <algorithm>
#include <map>
#include <set>
#include <stdexcept>

namespace analytics::validators::election {
namespace {
using Nano = boost::multiprecision::cpp_int;
constexpr size_t kMaxCandidates = 65535, kMaxFrozen = 65535;
constexpr size_t kMaxCredits = 200000, kMaxElections = 4096;

void mark(Evidence &e, Status s, std::string reason = {}) {
  e = {s, std::move(reason)};
}

Nano amount(const std::string &s) {
  if (s.empty() || s.size() > 37) // Grams = VarUInteger16, < 2^120
    throw std::runtime_error("amount_out_of_range");
  Nano n = 0;
  for (char c : s) {
    if (c < '0' || c > '9')
      throw std::runtime_error("amount_not_decimal");
    n = n * 10 + (c - '0');
  }
  if (n >= (Nano(1) << 120))
    throw std::runtime_error("amount_out_of_range");
  return n;
}

std::string grams(vm::CellSlice &cs) {
  auto x = block::tlb::t_Grams.as_integer_skip(cs);
  if (x.is_null())
    throw std::runtime_error("invalid_grams");
  auto s = x->to_dec_string();
  (void)amount(s);
  return s;
}

uint32_t word(vm::CellSlice &cs) {
  if (cs.size() < 32)
    throw std::runtime_error("truncated_uint32");
  return static_cast<uint32_t>(cs.fetch_ulong(32));
}

void clear_past(Observation &out) {
  out.past_present.reset();
  out.frozen.clear();
  out.frozen_root_hash.reset();
  out.frozen_total_nanoton.reset();
  out.bonuses_nanoton.reset();
  out.unfreeze_at.reset();
  out.stake_held_for.reset();
}

void fail_all(Observation &out, Status s, const std::string &why) {
  mark(out.roster, s, why);
  mark(out.applications, s, why);
  mark(out.past, s, why);
  mark(out.credits, s, why);
}

template <class F>
void component(Evidence &e, F &&fn) {
  try {
    fn();
  } catch (const vm::VmError &ex) {
    mark(e, Status::pending, std::string("cell_unavailable: ") + ex.get_msg());
  } catch (const std::exception &ex) {
    mark(e, Status::invalid, ex.what());
  }
}

void read_roster(Observation &out, const block::ConfigInfo &config) {
  auto cell = config.get_config_param(36);
  if (cell.is_null()) {
    mark(out.roster, Status::pending, "config_36_absent");
    return;
  }
  decode_elected_roster_cell(out, cell);
}

void read_past(Observation &out, const td::Ref<vm::Cell> &past) {
  if (!out.requested_vset_hash) {
    mark(out.past, Status::pending, "no_expected_vset_hash_or_config_36");
    return;
  }
  if (past.not_null())
    out.past_root_hash = past->get_hash().bits();
  vm::Dictionary dict{past, 32};
  unsigned matches = 0;
  size_t scanned = 0;
  for (auto it = dict.begin(); !it.eof(); ++it) {
    if (++scanned > kMaxElections)
      throw std::runtime_error("past_elections_limit_exceeded");
    const uint32_t id = static_cast<uint32_t>(td::BitArray<32>(it.cur_pos()).to_ulong());
    auto cs = *it.cur_value();
    auto unfreeze = word(cs), held = word(cs);
    td::Bits256 hash;
    td::Ref<vm::Cell> frozen, complaints;
    if (!cs.fetch_bits_to(hash) || !cs.fetch_maybe_ref(frozen))
      throw std::runtime_error("past_header_invalid");
    auto total = grams(cs), bonus = grams(cs);
    if (!cs.fetch_maybe_ref(complaints) || !cs.empty_ext())
      throw std::runtime_error("past_trailing_fields");
    bool chosen = out.requested_election_id ?
        id == *out.requested_election_id : hash == *out.requested_vset_hash;
    if (!chosen)
      continue;
    if (++matches != 1)
      throw std::runtime_error("ambiguous_vset_hash");
    if (hash != *out.requested_vset_hash)
      throw std::runtime_error("specified_election_vset_hash_mismatch");
    out.requested_election_id = id;
    out.past_present = true;
    out.unfreeze_at = unfreeze;
    out.stake_held_for = held;
    out.frozen_total_nanoton = total;
    out.bonuses_nanoton = bonus;
    if (frozen.not_null())
      out.frozen_root_hash = frozen->get_hash().bits();
    vm::Dictionary entries{frozen, 256};
    for (auto f = entries.begin(); !f.eof(); ++f) {
      if (out.frozen.size() >= kMaxFrozen)
        throw std::runtime_error("frozen_limit_exceeded");
      Frozen member;
      member.pubkey = td::BitArray<256>(f.cur_pos());
      auto fs = *f.cur_value();
      unsigned long long weight;
      if (!fs.fetch_bits_to(member.raw_holder) ||
          !fs.fetch_uint_to(64, weight))
        throw std::runtime_error("frozen_holder_or_weight_invalid");
      member.weight = weight;
      member.stake_nanoton = grams(fs);
      if (fs.size() != 1 || fs.size_refs() != 0)
        throw std::runtime_error("frozen_banned_invalid");
      member.banned = fs.fetch_ulong(1);
      out.frozen.push_back(member);
    }
  }
  if (!matches) {
    if (out.requested_election_id) {
      out.past_present = false; // complete, bounded full dictionary walk
      mark(out.past, Status::ready);
    } else {
      mark(out.past, Status::pending, "election_vset_hash_not_matched");
    }
    return;
  }
  verify_past(out);
}

void read_current(Observation &out, const td::Ref<vm::Cell> &current) {
  if (current.is_null()) {
    mark(out.applications, Status::pending, "current_election_absent");
    return;
  }
  out.current_root_hash = current->get_hash().bits();
  auto cs = vm::load_cell_slice(current);
  out.current_election_id = word(cs);
  word(cs); // elect_close
  grams(cs); // min_stake, not an accepted application
  out.accepted_nanoton = grams(cs);
  td::Ref<vm::Cell> members;
  if (!cs.fetch_maybe_ref(members) || cs.size() != 2 || cs.size_refs() != 0)
    throw std::runtime_error("current_election_layout_invalid");
  out.current_failed = cs.fetch_ulong(1);
  out.current_finished = cs.fetch_ulong(1);
  vm::Dictionary entries{members, 256};
  for (auto it = entries.begin(); !it.eof(); ++it) {
    if (out.candidates.size() >= kMaxCandidates)
      throw std::runtime_error("candidate_limit_exceeded");
    Candidate c;
    c.pubkey = td::BitArray<256>(it.cur_pos());
    auto value = *it.cur_value();
    c.stake_nanoton = grams(value);
    c.stake_at = word(value);
    c.max_factor = word(value);
    if (!value.fetch_bits_to(c.raw_holder) ||
        !value.fetch_bits_to(c.adnl) || !value.empty_ext())
      throw std::runtime_error("candidate_layout_invalid");
    out.candidates.push_back(c);
  }
  verify_applications(out);
}

void read_credits(Observation &out, const td::Ref<vm::Cell> &credits) {
  if (credits.not_null())
    out.credits_root_hash = credits->get_hash().bits();
  vm::Dictionary dict{credits, 256};
  for (auto it = dict.begin(); !it.eof(); ++it) {
    if (out.holder_credits.size() >= kMaxCredits)
      throw std::runtime_error("credits_limit_exceeded");
    Credit c;
    c.raw_holder = td::BitArray<256>(it.cur_pos());
    auto value = *it.cur_value();
    c.amount_nanoton = grams(value);
    if (!value.empty_ext())
      throw std::runtime_error("credit_trailing_fields");
    out.holder_credits.push_back(c);
  }
  verify_credits(out);
}

} // namespace

void decode_elected_roster_cell(Observation &out, td::Ref<vm::Cell> cell) {
  if (cell.is_null())
    throw std::runtime_error("config_36_absent");
  out.elected.clear();
  out.config36_hash = cell->get_hash().bits();
  // Native code validates the Hashmap key *set*, but its output is a vector
  // and normalizes legacy missing ADNL to zero. Read both facts from the
  // original cell, never from vector position or normalized ADNL.
  block::gen::ValidatorSet::Record_validators_ext ext;
  td::Ref<vm::Cell> dict_root;
  bool legacy_format = false;
  if (tlb::unpack_cell(cell, ext)) {
    out.since = ext.utime_since;
    out.until = ext.utime_until;
    out.total = static_cast<uint16_t>(ext.total);
    out.main = static_cast<uint16_t>(ext.main);
    out.total_weight = ext.total_weight;
    dict_root = ext.list->prefetch_ref();
  } else {
    legacy_format = true;
    block::gen::ValidatorSet::Record_validators legacy;
    if (!tlb::unpack_cell(cell, legacy))
      throw std::runtime_error("config_36_layout_invalid");
    out.since = legacy.utime_since;
    out.until = legacy.utime_until;
    out.total = static_cast<uint16_t>(legacy.total);
    out.main = static_cast<uint16_t>(legacy.main);
    out.total_weight = 0;
    dict_root = vm::Dictionary::construct_root_from(*legacy.list);
  }
  if (!out.total || !out.main || out.main > out.total ||
      out.since >= out.until)
    throw std::runtime_error("config_36_roster_header_invalid");

  auto native = block::Config::unpack_validator_set(cell, false);
  if (native.is_error())
    throw std::runtime_error("config_36_validator_set_invalid");
  const auto &set = *native.ok();
  if (set.total != out.total || set.main != out.main ||
      set.utime_since != out.since || set.utime_until != out.until ||
      set.list.size() != out.total)
    throw std::runtime_error("native_roster_header_mismatch");
  // Legacy #11 does not declare total_weight; use the independently computed
  // native sum, and validate it against exact raw entries below.
  if (legacy_format)
    out.total_weight = set.total_weight;
  if (out.total_weight != set.total_weight)
    throw std::runtime_error("native_roster_total_weight_mismatch");

  vm::Dictionary dict{dict_root, 16};
  for (auto it = dict.begin(); !it.eof(); ++it) {
    if (out.elected.size() >= kMaxFrozen)
      throw std::runtime_error("config_36_roster_limit_exceeded");
    Elected row;
    row.index = static_cast<uint16_t>(td::BitArray<16>(it.cur_pos()).to_ulong());
    auto value = *it.cur_value();
    td::Ref<vm::CellSlice> pubkey_slice;
    block::gen::ValidatorDescr::Record_validator_addr with_adnl;
    if (block::gen::t_ValidatorDescr.unpack(value, with_adnl) &&
        value.empty_ext()) {
      row.adnl = with_adnl.adnl_addr; // even explicit zero stays present
      row.weight = with_adnl.weight;
      pubkey_slice = with_adnl.public_key;
    } else {
      value = *it.cur_value();
      block::gen::ValidatorDescr::Record_validator legacy;
      if (!block::gen::t_ValidatorDescr.unpack(value, legacy) ||
          !value.empty_ext())
        throw std::runtime_error("config_36_descriptor_invalid");
      row.weight = legacy.weight;
      pubkey_slice = legacy.public_key;
      // ValidatorDescr#53 has no ADNL, including when native reports zero.
    }
    block::gen::SigPubKey::Record pk;
    if (!tlb::csr_unpack(pubkey_slice, pk))
      throw std::runtime_error("config_36_pubkey_invalid");
    row.pubkey = pk.pubkey;
    out.elected.push_back(row);
  }
  verify_elected(out);
  if (out.roster.status != Status::ready)
    throw std::runtime_error(out.roster.reason);

  // Do not assume native->list ordering equals Hashmap16 key ordering.
  // Compare by unique pubkey and full weight; native absence and explicit
  // zero ADNL both normalize to zero, raw descriptor kind remains authoritative.
  std::map<td::Bits256, const block::ValidatorDescr *> native_by_pubkey;
  for (const auto &m : set.list)
    if (!native_by_pubkey.emplace(m.pubkey.as_bits256(), &m).second)
      throw std::runtime_error("native_roster_duplicate_pubkey");
  for (const auto &m : out.elected) {
    auto it = native_by_pubkey.find(m.pubkey);
    if (it == native_by_pubkey.end() || it->second->weight != m.weight ||
        it->second->adnl_addr != m.adnl.value_or(td::Bits256{}))
      throw std::runtime_error("native_roster_member_mismatch");
  }
  std::sort(out.elected.begin(), out.elected.end(),
            [](const Elected &a, const Elected &b) { return a.index < b.index; });
}

void verify_elected(Observation &out) {
  std::set<uint16_t> indices;
  std::set<td::Bits256> keys;
  uint64_t sum = 0;
  bool ok = out.config36_hash && out.total > 0 && out.main > 0 &&
            out.main <= out.total && out.since < out.until &&
            out.elected.size() == out.total;
  for (size_t i = 0; i < out.elected.size(); ++i) {
    const auto &m = out.elected[i];
    if (m.index >= out.total || !indices.insert(m.index).second ||
        !keys.insert(m.pubkey).second || !m.weight ||
        m.weight > UINT64_MAX - sum)
      ok = false;
    else
      sum += m.weight;
  }
  if (!ok || indices.size() != out.total || !sum || sum != out.total_weight) {
    mark(out.roster, Status::invalid, "elected_roster_invariant");
    out.elected.clear();
  } else {
    mark(out.roster, Status::ready);
  }
}

void verify_past(Observation &out) {
  try {
    if (!out.past_present || !*out.past_present ||
        !out.requested_election_id || !out.requested_vset_hash ||
        !out.frozen_total_nanoton || !out.bonuses_nanoton ||
        !out.unfreeze_at || !out.stake_held_for || out.frozen.empty())
      throw std::runtime_error("past_missing_required_fields");
    Nano sum = 0;
    std::set<td::Bits256> keys;
    for (const auto &f : out.frozen) {
      if (!keys.insert(f.pubkey).second || !f.weight)
        throw std::runtime_error("frozen_duplicate_or_zero_weight");
      sum += amount(f.stake_nanoton);
    }
    if (sum != amount(*out.frozen_total_nanoton))
      throw std::runtime_error("frozen_sum_mismatch");
    (void)amount(*out.bonuses_nanoton);
    if (out.roster.status == Status::ready &&
        out.config36_hash == out.requested_vset_hash) {
      if (out.frozen.size() != out.elected.size())
        throw std::runtime_error("frozen_roster_count_mismatch");
      for (const auto &m : out.elected) {
        auto f = std::find_if(out.frozen.begin(), out.frozen.end(),
                              [&](const Frozen &x) { return x.pubkey == m.pubkey; });
        if (f == out.frozen.end() || f->weight != m.weight)
          throw std::runtime_error("frozen_roster_member_mismatch");
      }
    }
    mark(out.past, Status::ready);
  } catch (const std::exception &e) {
    mark(out.past, Status::invalid, e.what());
    clear_past(out);
  }
}

void verify_applications(Observation &out) {
  try {
    if (!out.current_election_id || !out.current_finished ||
        !*out.current_finished || !out.current_failed || *out.current_failed) {
      mark(out.applications, Status::pending, "current_election_not_final");
      out.candidates.clear();
      out.accepted_nanoton.reset();
      return;
    }
    if (out.roster.status != Status::ready || out.past.status != Status::ready ||
        !out.past_present || !*out.past_present ||
        !out.frozen_total_nanoton ||
        out.config36_hash != out.requested_vset_hash ||
        out.current_election_id != out.requested_election_id) {
      mark(out.applications, Status::pending, "final_election_not_linked_to_config_36");
      out.candidates.clear();
      out.accepted_nanoton.reset();
      return;
    }
    if (!out.accepted_nanoton || out.candidates.empty())
      throw std::runtime_error("final_candidates_missing");
    Nano sum = 0;
    std::map<td::Bits256, const Candidate *> keys;
    for (const auto &c : out.candidates) {
      if (!keys.emplace(c.pubkey, &c).second)
        throw std::runtime_error("candidate_duplicate_pubkey");
      sum += amount(c.stake_nanoton);
    }
    if (sum != amount(*out.accepted_nanoton))
      throw std::runtime_error("accepted_sum_mismatch");
    if (sum < amount(*out.frozen_total_nanoton))
      throw std::runtime_error("selected_exceeds_accepted");
    for (const auto &f : out.frozen) {
      auto c = keys.find(f.pubkey);
      if (c == keys.end() || c->second->raw_holder != f.raw_holder ||
          amount(f.stake_nanoton) > amount(c->second->stake_nanoton))
        throw std::runtime_error("selected_candidate_not_matched");
    }
    mark(out.applications, Status::ready);
  } catch (const std::exception &e) {
    mark(out.applications, Status::invalid, e.what());
    out.candidates.clear();
    out.accepted_nanoton.reset();
  }
}

void verify_credits(Observation &out) {
  try {
    Nano sum = 0;
    std::set<td::Bits256> holders;
    if (out.holder_credits.size() > kMaxCredits)
      throw std::runtime_error("credits_limit_exceeded");
    for (const auto &c : out.holder_credits) {
      if (!holders.insert(c.raw_holder).second)
        throw std::runtime_error("duplicate_credit_holder");
      sum += amount(c.amount_nanoton);
    }
    out.credits_total_nanoton = sum.convert_to<std::string>();
    mark(out.credits, Status::ready);
  } catch (const std::exception &e) {
    mark(out.credits, Status::invalid, e.what());
    out.holder_credits.clear();
    out.credits_total_nanoton.reset();
  }
}

td::Result<Observation> observe_election(
    const schema::MasterchainBlockDataState &loaded, const Input &input) {
  Observation out;
  out.network_zerostate = input.network_zerostate;
  out.mc_id = input.expected_mc_id;
  out.state_hash = input.expected_state_hash;
  out.state_update_verified = input.state_update_verified;
  out.requested_election_id = input.election_id;
  out.requested_vset_hash = input.expected_vset_hash;
  if (!valid_network_zerostate(input.network_zerostate) ||
      !input.expected_mc_id.is_masterchain() ||
      !input.expected_mc_id.is_valid() || !input.state_update_verified ||
      input.election_id.has_value() != input.expected_vset_hash.has_value() ||
      (input.election_id && *input.election_id == 0)) {
    fail_all(out, Status::pending, "unverified_or_invalid_input_identity");
    return out;
  }
  try {
    if (loaded.shard_blocks_.empty() ||
        !loaded.shard_blocks_.front().handle ||
        loaded.shard_blocks_.front().block_state.is_null() ||
        loaded.shard_blocks_.front().block_data.is_null()) {
      fail_all(out, Status::pending, "missing_mc_state");
      return out;
    }
    const auto &tip = loaded.shard_blocks_.front();
    if (tip.handle->id() != input.expected_mc_id ||
        tip.block_data->block_id() != input.expected_mc_id ||
        td::Bits256(tip.block_state->get_hash().bits()) != input.expected_state_hash) {
      fail_all(out, Status::invalid, "mc_id_or_state_hash_mismatch");
      return out;
    }
    auto root = tip.block_data->root_cell();
    block::gen::Block::Record block;
    block::gen::BlockInfo::Record info;
    block::gen::ShardStateUnsplit::Record state;
    if (root.is_null() || td::Bits256(root->get_hash().bits()) != input.expected_mc_id.root_hash ||
        !tlb::unpack_cell(root, block) || !tlb::unpack_cell(block.info, info) ||
        !tlb::unpack_cell(tip.block_state, state) || state.gen_utime != info.gen_utime)
      throw std::runtime_error("mc_block_or_post_state_invalid");
    out.gen_utime = info.gen_utime;
    auto config_result = block::ConfigInfo::extract_config(
        tip.block_state, input.expected_mc_id, block::ConfigInfo::needCapabilities);
    if (config_result.is_error())
      throw std::runtime_error("mc_config_invalid");
    auto config = config_result.move_as_ok();
    component(out.roster, [&] { read_roster(out, *config); });
    if (out.roster.status != Status::ready)
      out.elected.clear();
    if (!out.requested_vset_hash && out.roster.status == Status::ready)
      out.requested_vset_hash = out.config36_hash;
    auto address_cell = config->get_config_param(1);
    if (address_cell.is_null()) {
      mark(out.applications, Status::pending, "missing_config_1");
      mark(out.past, Status::pending, "missing_config_1");
      mark(out.credits, Status::pending, "missing_config_1");
      return out;
    }
    auto address_slice = vm::load_cell_slice(address_cell);
    td::Bits256 address;
    if (!address_slice.fetch_bits_to(address) || !address_slice.empty_ext())
      throw std::runtime_error("malformed_config_1");
    out.elector_address = address;
    vm::AugmentedDictionary accounts{vm::load_cell_slice_ref(state.accounts),
                                     256, block::tlb::aug_ShardAccounts};
    auto record = accounts.lookup(address);
    if (record.is_null()) {
      mark(out.applications, Status::pending, "missing_elector_account");
      mark(out.past, Status::pending, "missing_elector_account");
      mark(out.credits, Status::pending, "missing_elector_account");
      return out;
    }
    block::gen::ShardAccount::Record shard_account;
    if (!tlb::csr_unpack(std::move(record), shard_account) ||
        shard_account.account.is_null())
      throw std::runtime_error("elector_shard_account_invalid");
    out.elector_account_hash = shard_account.account->get_hash().bits();
    block::gen::Account::Record_account account;
    if (!tlb::unpack_cell(shard_account.account, account))
      throw std::runtime_error("elector_account_not_active");
    ton::WorkchainId wc;
    ton::StdSmcAddress acct_addr;
    if (!block::tlb::t_MsgAddressInt.extract_std_address(account.addr, wc, acct_addr) ||
        wc != -1 || acct_addr != address)
      throw std::runtime_error("elector_address_mismatch");
    block::gen::AccountStorage::Record storage;
    block::gen::AccountState::Record_account_active active;
    block::gen::StateInit::Record init;
    if (!tlb::csr_unpack(account.storage, storage) ||
        !tlb::csr_unpack(storage.state, active) ||
        !tlb::csr_unpack(active.x, init))
      throw std::runtime_error("elector_state_not_active");
    auto cs = *init.code, ds = *init.data;
    if (cs.fetch_ulong(1) != 1 || ds.fetch_ulong(1) != 1)
      throw std::runtime_error("elector_code_or_data_missing");
    auto code = cs.prefetch_ref(), data = ds.prefetch_ref();
    if (code.is_null() || data.is_null())
      throw std::runtime_error("elector_code_or_data_missing");
    out.elector_code_hash = code->get_hash().bits();
    out.elector_data_hash = data->get_hash().bits();
    if (!elector_code_enabled_for_decoder(*out.elector_code_hash,
                                         input.supported_elector_code_hashes)) {
      td::Bits256 reviewed;
      if (reviewed.from_hex(td::Slice(kReviewedElectorCodeHash.data(),
                                      kReviewedElectorCodeHash.size())) != 256)
        throw std::logic_error("invalid_pinned_elector_hash");
      const auto reason = *out.elector_code_hash == reviewed ?
          "elector_code_not_enabled_by_caller" : "elector_code_hash_not_reviewed";
      mark(out.applications, Status::pending, reason);
      mark(out.past, Status::pending, reason);
      mark(out.credits, Status::pending, reason);
      return out;
    }
    auto top = vm::load_cell_slice(data);
    td::Ref<vm::Cell> current, credits, past;
    if (!top.fetch_maybe_ref(current) || !top.fetch_maybe_ref(credits) ||
        !top.fetch_maybe_ref(past))
      throw std::runtime_error("elector_data_invalid");
    grams(top); // reserve, never stake
    word(top); // active ID
    td::Bits256 active_hash;
    if (!top.fetch_bits_to(active_hash) || !top.empty_ext())
      throw std::runtime_error("elector_data_trailing_fields");
    component(out.past, [&] { read_past(out, past); });
    if (out.past.status != Status::ready)
      clear_past(out);
    component(out.applications, [&] { read_current(out, current); });
    if (out.applications.status != Status::ready) {
      out.candidates.clear();
      out.accepted_nanoton.reset();
    }
    component(out.credits, [&] { read_credits(out, credits); });
    if (out.credits.status != Status::ready) {
      out.holder_credits.clear();
      out.credits_total_nanoton.reset();
    }
  } catch (const vm::VmError &e) {
    fail_all(out, Status::pending, std::string("mc_or_elector_cell_unavailable: ") + e.get_msg());
    out.elected.clear(); out.candidates.clear(); clear_past(out);
    out.holder_credits.clear(); out.accepted_nanoton.reset(); out.credits_total_nanoton.reset();
  } catch (const std::exception &e) {
    fail_all(out, Status::invalid, e.what());
    out.elected.clear(); out.candidates.clear(); clear_past(out);
    out.holder_credits.clear(); out.accepted_nanoton.reset(); out.credits_total_nanoton.reset();
  }
  return out;
}

} // namespace analytics::validators::election
