#include "NftEvents.h"

#include "td/utils/base64.h"
#include "common/checksum.h"
#include "IndexData.h"
#include "vm/boc.h"

#include <algorithm>
#include <map>
#include <set>
#include <tuple>

namespace assets_analytics::nft_events {
namespace {

bool valid_hash(const std::string& hash) {
  if (hash.size() != 44 || !td::is_base64(hash)) return false;
  auto decoded = td::base64_decode(hash);
  return decoded.is_ok() && decoded.ok().size() == 32 && td::base64_encode(decoded.ok()) == hash &&
         std::any_of(decoded.ok().begin(), decoded.ok().end(), [](char c) { return c != 0; });
}

bool valid(const BlockId& id) {
  return id.seqno != 0 && valid_hash(id.root_hash) && valid_hash(id.file_hash);
}

BlockId id_of(const ton::BlockIdExt& id) {
  return {id.id.workchain, static_cast<int64_t>(id.id.shard), id.id.seqno,
          td::base64_encode(id.root_hash.as_slice()), td::base64_encode(id.file_hash.as_slice())};
}

BlockId id_of(const schema::Block& b) {
  return {b.workchain, b.shard, b.seqno, b.root_hash, b.file_hash};
}

bool nonzero(const td::Bits256& hash) { return hash != td::Bits256::zero(); }

bool raw_incoming_matches(const schema::Transaction& tx, std::optional<std::string>& init_boc) {
  init_boc.reset();
  try {
    block::gen::Transaction::Record raw_tx;
    if (!tlb::unpack_cell(tx.raw, raw_tx)) return false;
    auto& incoming = raw_tx.r1.in_msg;
    if (incoming.is_null() || !incoming->have(1)) return false;
    // TL-B Maybe is an unsigned bit. prefetch_long(1) sign-extends just$1
    // to -1; comparing that signed value with 1 rejects every incoming message.
    bool present = incoming->prefetch_ulong(1) == 1;
    if (present != tx.in_msg.has_value()) return false;
    if (!present) return true;
    auto raw_msg = incoming->prefetch_ref();
    if (raw_msg.is_null() || raw_msg->get_hash().as_bits256() != tx.in_msg->hash) return false;
    block::gen::Message::Record msg;
    if (!tlb::type_unpack_cell(raw_msg, block::gen::t_Message_Any, msg)) return false;
    auto init = msg.init.write();
    bool has_init = init.fetch_ulong(1) == 1;
    if (has_init != tx.in_msg->init_state.not_null()) return false;
    if (!has_init) return !tx.in_msg->init_state_boc.has_value();
    bool by_ref = init.fetch_ulong(1) == 1;
    auto raw_init = by_ref ? init.fetch_ref() : vm::CellBuilder().append_cellslice(init).finalize();
    if (raw_init.is_null() || raw_init->get_hash() != tx.in_msg->init_state->get_hash() ||
        !tx.in_msg->init_state_boc || tx.in_msg->init_state_boc->empty()) return false;
    // DataParser::parse_message strips Maybe/Either from inline StateInit and
    // dereferences ref StateInit. convert::to_bytes stores BASE64 of the
    // deterministic WithCRC32C serialization, not binary BoC. Compare that exact
    // parser representation with the raw-message StateInit serialization. A root
    // hash check alone would miss trailing bytes/unreachable cells/extra roots.
    auto decoded_boc = td::base64_decode(*tx.in_msg->init_state_boc);
    if (decoded_boc.is_error() || td::base64_encode(decoded_boc.ok()) != *tx.in_msg->init_state_boc)
      return false;
    auto expected_boc = vm::std_boc_serialize(raw_init, vm::BagOfCells::WithCRC32C);
    if (expected_boc.is_error() || expected_boc.ok().as_slice() != td::Slice(decoded_boc.ok()))
      return false;
    init_boc = decoded_boc.move_as_ok();
    return true;
  } catch (const vm::VmError&) {
    return false;
  }
}

bool known(schema::AccountStatus status) {
  return status == schema::nonexist || status == schema::uninit || status == schema::frozen ||
         status == schema::active;
}

Status convert(schema::AccountStatus status) {
  switch (status) {
    case schema::nonexist: return Status::nonexist;
    case schema::uninit: return Status::uninit;
    case schema::frozen: return Status::frozen;
    case schema::active: return Status::active;
  }
  return Status::nonexist; // unreachable after known() check
}

struct Execution {
  bool committed{};
  bool accepted_init{};
};

Execution execution(const schema::Transaction& tx) {
  const schema::TrComputePhase* compute = nullptr;
  bool aborted = true;
  if (const auto* d = std::get_if<schema::TransactionDescr_ord>(&tx.description)) {
    compute = &d->compute_ph; aborted = d->aborted;
  } else if (const auto* d = std::get_if<schema::TransactionDescr_tick_tock>(&tx.description)) {
    compute = &d->compute_ph; aborted = d->aborted;
  } else if (const auto* d = std::get_if<schema::TransactionDescr_split_prepare>(&tx.description)) {
    compute = &d->compute_ph; aborted = d->aborted;
  } else if (const auto* d = std::get_if<schema::TransactionDescr_merge_install>(&tx.description)) {
    compute = &d->compute_ph; aborted = d->aborted;
  }
  const auto* vm = compute ? std::get_if<schema::TrComputePhase_vm>(compute) : nullptr;
  // A failed action phase alone need not undo a non-aborted compute/data
  // transition; the transaction's resulting account-cell hash is the lead.
  bool committed = vm && vm->success && !aborted;
  return {committed, committed && vm->msg_state_used && vm->account_activated &&
                         tx.orig_status != schema::active && tx.end_status == schema::active};
}

Result fail(BlockId mc, const char* error) {
  Result result;
  result.mc_anchor = std::move(mc);
  result.error = error;
  return result;
}

}  // namespace

Result extract(const ParsedBlock& parsed, const BlockId& expected_mc, Budget budget) {
  if (!valid(expected_mc) || expected_mc.workchain != -1 || !budget.max_blocks ||
      !budget.max_transactions || !budget.max_candidates || !budget.max_evidence_bytes)
    return fail(expected_mc, "invalid MC anchor or zero budget");
  const auto& diff = parsed.mc_block_.shard_blocks_diff_;
  if (parsed.blocks_.empty() || parsed.blocks_.size() > budget.max_blocks ||
      diff.size() != parsed.blocks_.size())
    return fail(expected_mc, "parsed blocks do not equal bounded first-included diff");

  size_t total = 0;
  size_t used = 0;
  std::vector<BlockId> parsed_ids, diff_ids;
  parsed_ids.reserve(diff.size());
  diff_ids.reserve(diff.size());
  for (size_t i = 0; i < diff.size(); ++i) {
    if (diff[i].block_data.is_null()) return fail(expected_mc, "missing diff block data");
    auto raw_root = diff[i].block_data->root_cell();
    // BlockData::file_hash() only echoes metadata; hash original serialized BoC.
    auto boc = diff[i].block_data->data();
    if (boc.empty() || td::sha256_bits256(boc.as_slice()) != diff[i].block_data->block_id().file_hash ||
        raw_root.is_null() ||
        raw_root->get_hash().as_bits256() != diff[i].block_data->block_id().root_hash)
      return fail(expected_mc, "raw block root/file hash does not match full diff ID");
    parsed_ids.push_back(id_of(parsed.blocks_[i]));
    diff_ids.push_back(id_of(diff[i].block_data->block_id()));
    const size_t bytes = 2 * sizeof(BlockId) + parsed_ids.back().root_hash.size() +
                         parsed_ids.back().file_hash.size() + diff_ids.back().root_hash.size() +
                         diff_ids.back().file_hash.size();
    if (!bounded_add(bytes, used, budget.max_evidence_bytes))
      return fail(expected_mc, "source manifest byte cap exceeded");
  }
  if (!valid_diff_layout(expected_mc, parsed_ids, diff_ids, budget))
    return fail(expected_mc, "missing, duplicate or non-diff source block");
  for (const auto& id : parsed_ids) {
    if (!valid(id)) return fail(expected_mc, "invalid source block hash");
  }
  std::set<std::string> seen_transactions;
  Result out;
  out.mc_anchor = expected_mc;
  for (size_t i = 0; i < diff.size(); ++i) {
    const auto& block = parsed.blocks_[i];
    const BlockId source = id_of(block);
    if (diff[i].block_data.is_null() || !valid(source) ||
        !same_block(source, id_of(diff[i].block_data->block_id())))
      return fail(expected_mc, "missing or inconsistent source block ID/hash");
    if (i == 0) {
      if (!same_block(source, expected_mc)) return fail(expected_mc, "explicit MC anchor mismatch");
    } else if (source.workchain == -1) {
      return fail(expected_mc, "additional MC block in diff");
    }
    if (!block.mc_block_workchain || !block.mc_block_shard || !block.mc_block_seqno ||
        *block.mc_block_workchain != expected_mc.workchain ||
        *block.mc_block_shard != expected_mc.shard || *block.mc_block_seqno != expected_mc.seqno)
      return fail(expected_mc, "source block not linked to explicit MC anchor");
    if (block.gen_utime < 0 || block.start_lt >= block.end_lt ||
        !bounded_count(block.transactions.size(), total, budget.max_transactions))
      return fail(expected_mc, "invalid block time/LT or transaction cap exceeded");
    // Last tx in this *block*, not the final post-state in account_states_.
    std::map<std::string, OrderedTx> last;
    for (const auto& tx : block.transactions) {
      const auto canonical_address = canonical_account_address(tx.account.workchain, tx.account.addr.to_hex());
      if (!canonical_address) return fail(expected_mc, "invalid raw transaction account address");
      const auto& address = *canonical_address;
      if (tx.account.workchain != source.workchain || tx.mc_seqno != expected_mc.seqno ||
          tx.raw.is_null() || !nonzero(tx.hash) || tx.raw->get_hash().as_bits256() != tx.hash ||
          !nonzero(tx.account_state_hash_before) || !nonzero(tx.account_state_hash_after) ||
          !known(tx.orig_status) || !known(tx.end_status) ||
          tx.lt < block.start_lt || tx.lt >= block.end_lt || tx.now != static_cast<uint32_t>(block.gen_utime))
        return fail(expected_mc, "missing or inconsistent raw transaction/state evidence");
      if (!bounded_add(64, used, budget.max_evidence_bytes))
        return fail(expected_mc, "transaction identity byte cap exceeded");
      if (!seen_transactions.insert(tx.hash.to_hex()).second)
        return fail(expected_mc, "duplicate raw transaction hash");
      OrderedTx item{address, tx.hash.to_hex(), tx.lt, tx.prev_trans_lt,
                     tx.prev_trans_hash.to_hex(), tx.account_state_hash_before.to_hex(),
                     tx.account_state_hash_after.to_hex(), convert(tx.orig_status),
                     convert(tx.end_status)};
      auto prior = last.find(address);
      if (prior != last.end() && !contiguous(prior->second, item))
        return fail(expected_mc, "noncontiguous same-account transactions in block");
      last[address] = std::move(item);
      const bool changed = tx.account_state_hash_before != tx.account_state_hash_after;
      if (tx.orig_status != tx.end_status && !changed)
        return fail(expected_mc, "state status changed without account-cell hash change");
      if (tx.in_msg && (tx.in_msg->init_state.is_null() != !tx.in_msg->init_state_boc.has_value()))
        return fail(expected_mc, "inconsistent incoming StateInit cell/BoC");
      if (tx.in_msg && tx.in_msg->init_state_boc &&
          tx.in_msg->init_state_boc->size() > budget.max_evidence_bytes - used)
        return fail(expected_mc, "incoming StateInit BoC exceeds evidence budget");
      // The parsed message, its attached init cell and serialized BoC must all
      // agree with the *raw transaction*, not merely with each other.
      std::optional<std::string> init_boc;
      if (!raw_incoming_matches(tx, init_boc))
        return fail(expected_mc, "incoming message/StateInit differs from raw transaction or BoC");
      auto exec = execution(tx);
      if (decide({convert(tx.orig_status), convert(tx.end_status), exec.committed, changed}) ==
          Decision::not_candidate) continue;
      if (out.candidates.size() >= budget.max_candidates)
        return fail(expected_mc, "candidate cap exceeded");
      Candidate c;
      c.source_block = source;
      c.mc_anchor = expected_mc;
      c.account = address;
      c.transaction_hash = tx.hash.to_hex();
      c.lt = tx.lt;
      c.now = tx.now;
      c.orig_status = convert(tx.orig_status);
      c.end_status = convert(tx.end_status);
      c.state_hash_before = tx.account_state_hash_before.to_hex();
      c.state_hash_after = tx.account_state_hash_after.to_hex();
      c.reason = tx.orig_status == schema::active ? "changed_active_state; init_unverified" :
                                                   "became_active; init_unverified";
      if (tx.in_msg && tx.in_msg->init_state.not_null()) {
        if (tx.in_msg->init_state_boc->empty())
          return fail(expected_mc, "empty supplied StateInit BoC");
        c.supplied_state_init_hash = tx.in_msg->init_state->get_hash().to_hex();
        if (exec.accepted_init) {
          c.accepted_state_init_hash = c.supplied_state_init_hash;
          c.accepted_state_init_boc = std::move(init_boc);
        }
      }
      // Budget the *owned* evidence, including per-candidate full block IDs and
      // raw BoC, before retaining it. Never truncate a candidate or its evidence.
      size_t bytes = sizeof(Candidate) + c.account.size() + c.transaction_hash.size() +
                     c.state_hash_before.size() + c.state_hash_after.size() + c.reason.size() +
                     2 * (source.root_hash.size() + source.file_hash.size()) +
                     (c.supplied_state_init_hash ? c.supplied_state_init_hash->size() : 0) +
                     (c.accepted_state_init_hash ? c.accepted_state_init_hash->size() : 0);
      if (!bounded_add(bytes, used, budget.max_evidence_bytes) ||
          (c.accepted_state_init_boc &&
           !bounded_add(c.accepted_state_init_boc->size(), used, budget.max_evidence_bytes)))
        return fail(expected_mc, "evidence byte cap exceeded");
      out.candidates.push_back(std::move(c));
    }
  }
  out.examined_transactions = total;
  std::sort(out.candidates.begin(), out.candidates.end(), candidate_less);
  return out;
}

}  // namespace assets_analytics::nft_events
