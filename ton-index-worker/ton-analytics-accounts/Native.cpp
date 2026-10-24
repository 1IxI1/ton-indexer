#include "Native.h"

#include "DataParser.h"
#include "crypto/block/block-auto.h"
#include "crypto/block/block.h"
#include "crypto/block/block-parse.h"
#include "crypto/vm/dict.h"
#include "crypto/vm/boc.h"
#include "td/utils/crypto.h"
#include "ton/ton-shard.h"

#include <map>
#include <set>
#include <stdexcept>

namespace tonstat::accounts {
namespace {

void check(bool ok, const char* what) {
  if (!ok) throw std::runtime_error(what);
}

BlockId id_of(const ton::BlockIdExt& id) {
  return {id.id.workchain, id.id.shard, id.id.seqno,
          id.root_hash.to_hex(), id.file_hash.to_hex()};
}

block::gen::Block::Record raw_block(const schema::BlockDataState& entry) {
  check(!entry.block_data.is_null() && !entry.block_state.is_null() && static_cast<bool>(entry.handle),
        "missing raw block, post-state or handle");
  check(entry.block_data->block_id() == entry.handle->id(), "block/handle ID mismatch");
  const auto bytes = entry.block_data->data();
  td::Bits256 file_hash;
  td::sha256(bytes.as_slice(), file_hash.as_slice());
  check(file_hash == entry.handle->id().file_hash &&
        entry.block_data->file_hash() == entry.handle->id().file_hash,
        "raw BoC SHA256/file_hash differs from full block ID");
  auto parsed_boc = vm::std_boc_deserialize(bytes.as_slice());
  check(parsed_boc.is_ok(), "cannot deserialize bytes of authenticated block BoC");
  const auto root = entry.block_data->root_cell();
  check(!root.is_null() && root->get_hash().as_bits256() == entry.handle->id().root_hash &&
        parsed_boc.move_as_ok()->get_hash() == root->get_hash(),
        "raw BoC root / cached block root differs from handle");
  block::gen::Block::Record block;
  check(tlb::unpack_cell(root, block), "malformed raw Block");
  block::gen::BlockInfo::Record info;
  check(tlb::unpack_cell(block.info, info), "malformed raw BlockInfo");
  const block::ShardId shard{info.shard};
  check(shard.is_valid() && info.seq_no == entry.handle->id().id.seqno &&
        shard.workchain_id == entry.handle->id().id.workchain &&
        shard.shard_pfx == entry.handle->id().id.shard &&
        info.not_master == !entry.handle->id().is_masterchain(),
        "raw block header shard/seqno does not match full block ID");
  block::gen::MERKLE_UPDATE::Record update;
  check(tlb::type_unpack_cell(block.state_update, block::gen::t_MERKLE_UPDATE_ShardState, update) &&
        update.new_hash == entry.block_state->get_hash().as_bits256(),
        "post-state hash not linked by raw block update");
  return block;
}

// MC state is the authoritative source of expected top shard IDs. Comparing it
// against DbScanner's fetched vector prevents truncated input from masquerading
// as a complete snapshot even when all *provided* tips were scanned.
Anchor extract_anchor(const schema::MasterchainBlockDataState& input,
                      const std::string& network, const std::string& zerostate,
                      const Caps& caps) {
  check(caps.max_snapshot_tips && caps.max_boc_bytes &&
        input.shard_blocks_.size() <= caps.max_snapshot_tips,
        "snapshot tip cap exceeded");
  for (const auto& tip : input.shard_blocks_) {
    check(!tip.block_data.is_null() && tip.block_data->data().size() <= caps.max_boc_bytes,
          "snapshot raw BoC cap exceeded");
  }
  check(!input.shard_blocks_.empty(), "missing MC tip");
  const auto& mc = input.shard_blocks_.front();
  check(static_cast<bool>(mc.handle) && mc.handle->id().is_masterchain(), "MC must be first tip");
  (void)raw_block(mc);
  block::gen::ShardStateUnsplit::Record state;
  block::gen::McStateExtra::Record extra;
  block::ShardConfig shards;
  check(tlb::unpack_cell(mc.block_state, state) && !state.custom.is_null() &&
        tlb::unpack_cell(state.custom->prefetch_ref(), extra) &&
        shards.unpack(extra.shard_hashes), "invalid MC shard configuration");
  Anchor anchor{network, zerostate, id_of(mc.handle->id()),
                mc.block_state->get_hash().to_hex(), {}};
  std::set<BlockId> expected{anchor.mc};
  for (const auto& tip : shards.get_shard_hash_ids_ext(true)) {
    check(tip.id.seqno > 0, "zero-seqno tip requires separate zerostate proof");
    check(expected.insert(id_of(tip)).second, "duplicate MC-config tip");
  }
  std::set<BlockId> actual;
  for (const auto& tip : input.shard_blocks_) {
    (void)raw_block(tip);
    const auto id = id_of(tip.handle->id());
    check(actual.insert(id).second, "duplicate fetched snapshot tip");
    anchor.tips.push_back({id, tip.block_state->get_hash().to_hex()});
  }
  check(actual == expected, "fetched tips differ from MC state manifest");
  require_anchor(anchor);
  return anchor;
}

Status from_tlb(char value) {
  switch (value) {
    case 0: return Status::uninit;
    case 1: return Status::frozen;
    case 2: return Status::active;
    case 3: return Status::nonexist;
    default: throw std::runtime_error("invalid raw TL-B account status");
  }
}

Status account_status(td::Ref<vm::Cell> account_cell, td::Bits256 key,
                      const schema::BlockDataState& tip,
                      const block::gen::ShardAccount::Record& wrapper) {
  check(!account_cell.is_null(), "missing ShardAccount.account cell");
  // A stored account_none is NOT evidence of an existing account and is not
  // silently counted as uninit. A full scan of such a state needs investigation.
  block::gen::Account::Record_account account;
  check(tlb::unpack_cell(account_cell, account), "nonexistent/malformed account stored in ShardAccounts");
  block::gen::AccountStorage::Record storage;
  check(tlb::csr_unpack(account.storage, storage), "malformed AccountStorage");
  auto parsed = ParseQuery::parse_account(account_cell, 0,
                                          wrapper.last_trans_hash, wrapper.last_trans_lt);
  check(parsed.is_ok(), "native Account or StateInit decode failed");
  const auto account_result = parsed.move_as_ok();
  check(account_result.account.workchain == tip.handle->id().id.workchain &&
        account_result.account.addr == key, "account address differs from dictionary key");
  const auto tag = block::gen::t_AccountState.get_tag(storage.state.write());
  switch (tag) {
    case block::gen::AccountState::account_uninit: return Status::uninit;
    case block::gen::AccountState::account_active: return Status::active;
    case block::gen::AccountState::account_frozen: return Status::frozen;
    default: throw std::runtime_error("invalid TL-B AccountState tag");
  }
}

void scan_tip(const schema::BlockDataState& tip, Snapshot& result, std::uint64_t limit) {
  block::gen::ShardStateUnsplit::Record state;
  check(tlb::unpack_cell(tip.block_state, state), "invalid ShardStateUnsplit");
  const block::ShardId shard{state.shard_id};
  check(shard.is_valid() && shard.workchain_id == tip.handle->id().id.workchain &&
        shard.shard_pfx == tip.handle->id().id.shard && state.seq_no == tip.handle->id().id.seqno,
        "state shard/seqno differs from block ID");
  vm::AugmentedDictionary dict{vm::load_cell_slice_ref(state.accounts), 256,
                               block::tlb::aug_ShardAccounts};
  td::Bits256 key = td::Bits256::zero();
  bool first = true;
  for (;;) {
    // Request one extra key to prove EOF when count==limit. Never touch its
    // account cell if the budget has already been exhausted.
    const auto old = key;
    auto value = dict.vm::DictionaryFixed::lookup_nearest_key(key.bits(), 256, true, first);
    if (value.is_null()) break;
    check(first || old.compare(key) < 0, "non-monotonic account dictionary");
    if (result.visited == limit) return;
    first = false;
    check(ton::shard_contains(ton::ShardIdFull(block::ShardId(state.shard_id)),
                              ton::extract_addr_prefix(tip.handle->id().id.workchain, key)),
          "account key outside state shard");
    block::gen::ShardAccount::Record wrapper;
    check(tlb::csr_unpack(dict.extract_value(value), wrapper), "malformed ShardAccount");
    const auto status = account_status(wrapper.account, key, tip, wrapper);
    check(status != Status::nonexist, "nonexist is not stored as existing account");
    if (component(result.counts, status) == UINT64_MAX) throw std::overflow_error("count overflow");
    ++component(result.counts, status);
    ++result.visited;
  }
  ++result.scanned_tips;
}

void decode_transactions(const schema::BlockDataState& entry, NewBlock& out,
                         std::size_t& tx_count, const Caps& caps) {
  const auto block = raw_block(entry);
  block::gen::BlockExtra::Record extra;
  check(tlb::unpack_cell(block.extra, extra), "invalid BlockExtra");
  vm::AugmentedDictionary accounts{vm::load_cell_slice_ref(extra.account_blocks), 256,
                                   block::tlb::aug_ShardAccountBlocks};
  td::Bits256 addr = td::Bits256::zero();
  bool first = true;
  for (;;) {
    const auto old = addr;
    auto value = accounts.vm::DictionaryFixed::lookup_nearest_key(addr.bits(), 256, true, first);
    if (value.is_null()) break;
    check(first || old.compare(addr) < 0, "non-monotonic AccountBlocks");
    first = false;
    block::gen::AccountBlock::Record ab;
    check(tlb::csr_unpack(accounts.extract_value(value), ab) && ab.account_addr == addr,
          "malformed AccountBlock / wrong account key");
    vm::AugmentedDictionary txs{vm::DictNonEmpty(), ab.transactions, 64,
                                block::tlb::aug_AccountTransactions};
    block::gen::HASH_UPDATE::Record account_update;
    check(tlb::type_unpack_cell(ab.state_update, block::gen::t_HASH_UPDATE_Account,
                                account_update), "invalid AccountBlock state update");
    td::BitArray<64> lt{(long long)0};
    bool first_tx = true;
    td::Bits256 prior_state_hash, prior_tx_hash;
    std::uint64_t prior_tx_lt = 0;
    for (;;) {
      const auto prev_lt = lt;
      auto ref = txs.vm::DictionaryFixed::lookup_nearest_key(lt.bits(), 64, true, first_tx);
      if (ref.is_null()) break;
      const bool is_first = first_tx;
      check(first_tx || prev_lt < lt, "non-monotonic Transaction dictionary");
      first_tx = false;
      auto tx_cell = txs.extract_value_ref(ref);
      block::gen::Transaction::Record tx;
      check(!tx_cell.is_null() && tlb::unpack_cell(tx_cell, tx), "malformed raw Transaction");
      check(tx.account_addr == addr && tx.lt == lt.to_ulong(), "transaction key / LT mismatch");
      block::gen::HASH_UPDATE::Record update;
      check(tlb::type_unpack_cell(tx.state_update, block::gen::t_HASH_UPDATE_Account, update),
            "invalid Transaction state update");
      if (is_first) {
        check(update.old_hash == account_update.old_hash,
              "first tx state differs from AccountBlock old state");
      } else {
        check(update.old_hash == prior_state_hash && tx.prev_trans_lt == prior_tx_lt &&
              tx.prev_trans_hash == prior_tx_hash,
              "raw transactions in AccountBlock are discontinuous");
      }
      if (tx_count == caps.max_transactions || out.transactions.size() == caps.max_transactions)
        throw std::runtime_error("raw transaction cap exceeded");
      ++tx_count;
      out.transactions.push_back({{out.id.workchain, addr.to_hex()}, tx.lt,
                                   tx_cell->get_hash().to_hex(),
                                   from_tlb(tx.orig_status), from_tlb(tx.end_status),
                                   tx.prev_trans_lt, tx.prev_trans_hash.to_hex(),
                                   update.old_hash.to_hex(), update.new_hash.to_hex()});
      prior_state_hash = update.new_hash;
      prior_tx_hash = tx_cell->get_hash().as_bits256();
      prior_tx_lt = tx.lt;
    }
    check(!first_tx, "empty AccountBlock transactions");
    check(out.transactions.back().new_state_hash == account_update.new_hash.to_hex(),
          "last tx state differs from AccountBlock new state");
  }
}

} // namespace

Snapshot scan_snapshot(const schema::MasterchainBlockDataState& input,
                       const std::string& network, const std::string& zerostate,
                       std::uint64_t limit, bool allow_full, Caps caps) {
  check(limit > 0, "zero snapshot budget");
  Snapshot s;
  s.anchor = extract_anchor(input, network, zerostate, caps);
  for (const auto& tip : input.shard_blocks_) {
    try {
      scan_tip(tip, s, limit);
    } catch (const vm::VmError&) {
      throw std::runtime_error("unreadable/malformed ShardAccounts cell");
    }
    if (s.scanned_tips < (&tip - input.shard_blocks_.data()) + 1) break;
  }
  finish_snapshot(s, allow_full, true);
  return s;
}

Step decode_step(const schema::MasterchainBlockDataState& input, const Anchor& previous,
                 const std::string& network, const std::string& zerostate, Caps caps) {
  require_anchor(previous);
  check(caps.max_blocks && caps.max_transactions && caps.max_tracked_accounts &&
        caps.max_boc_bytes && caps.max_snapshot_tips,
        "zero delta cap");
  Step s;
  s.next = extract_anchor(input, network, zerostate, caps);
  s.previous_mc = previous.mc;
  check(s.next.mc.seqno == previous.mc.seqno + 1, "MC seqno gap");
  check(input.shard_blocks_diff_.size() <= caps.max_blocks, "raw block cap exceeded");
  std::map<BlockId, std::string> predecessor_states;
  for (const auto& tip : previous.tips)
    predecessor_states.emplace(tip.id, tip.state_root);
  for (const auto& entry : input.shard_blocks_diff_) {
    check(static_cast<bool>(entry.handle) && !entry.block_state.is_null() &&
          !entry.block_data.is_null(), "null diff handle/state/block");
    check(entry.block_data->data().size() <= caps.max_boc_bytes,
          "raw BoC cap exceeded");
    check(predecessor_states.emplace(id_of(entry.handle->id()),
                                     entry.block_state->get_hash().to_hex()).second,
          "repeated new block or baseline tip");
  }
  std::set<BlockId> new_ids;
  std::map<BlockId, std::vector<BlockId>> children;
  std::size_t tx_count = 0;
  for (const auto& entry : input.shard_blocks_diff_) {
    const auto id = id_of(entry.handle->id());
    check(new_ids.insert(id).second, "repeated first-included block");
    const auto raw = raw_block(entry);
    block::gen::MERKLE_UPDATE::Record update;
    check(tlb::type_unpack_cell(raw.state_update, block::gen::t_MERKLE_UPDATE_ShardState,
                                update), "malformed raw state update");
    std::vector<ton::BlockIdExt> predecessors;
    ton::BlockIdExt mc_ref;
    bool after_split = false;
    auto status = block::unpack_block_prev_blk_ext(entry.block_data->root_cell(),
                                                   entry.handle->id(), predecessors,
                                                   mc_ref, after_split);
    check(status.is_ok() && !predecessors.empty() && predecessors.size() <= 2,
          "invalid raw block predecessors");
    NewBlock b;
    b.id = id;
    b.old_state_hash = update.old_hash.to_hex();
    b.post_state_hash = entry.block_state->get_hash().to_hex();
    for (const auto& p : predecessors) {
      b.prev.push_back(id_of(p));
      children[id_of(p)].push_back(id);
    }
    // TON split/merge state transformations are not a simple equality to the
    // parent state hash. Until native transform/proof verification is wired in,
    // deliberately return a pending step instead of claiming continuity.
    if (after_split || b.prev.size() == 2 || b.prev.front().shard != id.shard) {
      s.pending_reason = "split/merge old-state transform not verified";
      return s;
    }
    auto parent = predecessor_states.find(b.prev.front());
    check(parent != predecessor_states.end() && update.old_hash.to_hex() == parent->second,
          "raw shard old-state hash not linked to predecessor post-state");
    if (id.workchain == -1) {
      check(id == s.next.mc && b.prev.size() == 1 && b.prev.front() == previous.mc,
            "invalid MC ancestry");
    } else if (b.prev.size() == 2) {
      check(ton::shard_is_parent(id.shard, b.prev[0].shard) &&
            ton::shard_is_parent(id.shard, b.prev[1].shard) &&
            ton::shard_is_sibling(b.prev[0].shard, b.prev[1].shard),
            "invalid merge ancestry");
    } else {
      check(after_split ? ton::shard_is_parent(b.prev[0].shard, id.shard)
                        : b.prev[0].shard == id.shard, "invalid split ancestry");
    }
    try { decode_transactions(entry, b, tx_count, caps); }
    catch (const vm::VmError&) { throw std::runtime_error("unreadable raw transaction dictionary"); }
    s.newly_included.push_back(std::move(b));
  }
  check(new_ids.count(s.next.mc) == 1, "new MC missing");
  // A split has exactly two direct children; no replacement of a shard by only
  // one child is a valid complete frontier. Merge has both parent tips in prev.
  for (const auto& [p, descendants] : children) {
    if (descendants.size() > 1)
      check(descendants.size() == 2 && ton::shard_is_sibling(descendants[0].shard,
                                                            descendants[1].shard) &&
            ton::shard_is_parent(p.shard, descendants[0].shard),
            "missing/duplicated split sibling");
  }
  // Native scanner diff is not a first-inclusion proof by itself: check every
  // new handle against the anchor's MC reference, plus the complete frontier
  // in Counter::apply. Different inclusion policies must supply a new adapter.
  for (const auto& entry : input.shard_blocks_diff_)
    if (!entry.handle->id().is_masterchain())
      check(entry.handle->inited_masterchain_ref_block() &&
            entry.handle->masterchain_ref_block() == s.next.mc.seqno,
            "shard block not first-included at MC anchor");
  s.inclusion_and_topology_verified = true;
  s.raw_identity_verified = true;
  s.state_linkage_verified = true;
  s.pending_reason = "baseline account status/LT/hash witness not verified";
  return s;
}

} // namespace tonstat::accounts
