#include "DnsAuctionEvents.h"

#include "../IndexData.h"
#include "common/checksum.h"
#include "td/utils/base64.h"
#include "td/utils/crypto.h"

#include <limits>
#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace assets_analytics::dns {
namespace {

std::optional<std::string> address(const block::StdAddress& a) {
  return canonical_account_address(a.workchain, a.addr.to_hex());
}

BlockId block_id(const schema::Block& block) {
  return {block.workchain, block.shard, block.seqno, block.root_hash, block.file_hash};
}

BlockId block_id(const ton::BlockIdExt& id) {
  return {id.id.workchain, static_cast<int64_t>(id.id.shard), id.id.seqno,
          td::base64_encode(id.root_hash.as_slice()), td::base64_encode(id.file_hash.as_slice())};
}

Message message(const schema::Message& src) {
  Message out;
  out.hash = src.hash.to_hex();
  out.source = src.source;
  out.destination = src.destination;
  if (src.opcode) out.opcode = static_cast<uint32_t>(*src.opcode);
  if (src.value && src.value->grams.not_null())
    out.value_nanoton = src.value->grams->to_dec_string();
  out.bounced = src.bounced;
  return out;
}

bool aborted(const schema::Transaction& tx) {
  if (auto* ord = std::get_if<schema::TransactionDescr_ord>(&tx.description)) return ord->aborted;
  if (auto* tick = std::get_if<schema::TransactionDescr_tick_tock>(&tx.description)) return tick->aborted;
  if (auto* split = std::get_if<schema::TransactionDescr_split_prepare>(&tx.description)) return split->aborted;
  if (auto* merge = std::get_if<schema::TransactionDescr_merge_prepare>(&tx.description)) return merge->aborted;
  if (auto* merge = std::get_if<schema::TransactionDescr_merge_install>(&tx.description)) return merge->aborted;
  // Non-ordinary/unknown descriptor: never classify it as a successful bid.
  return true;
}

Batch error(const char* reason) {
  Batch batch;
  batch.reason = reason;
  return batch;
}

}  // namespace

Batch extract_dns_auction_candidates(const ParsedBlock& parsed, const Request& request) {
  const Limits& cap = request.limits;
  // Validate the entire first-included block manifest, including empty blocks.
  // shard_blocks_ is a CURRENT TIP set, and is deliberately never read here.
  if (!cap.max_blocks || cap.max_blocks > 4096 || !cap.max_transactions ||
      cap.max_transactions > 10000 || !cap.max_messages_per_tx ||
      cap.max_messages_per_tx > 256 || !cap.max_total_messages ||
      cap.max_total_messages > 50000 || !cap.max_provenance_bytes ||
      cap.max_provenance_bytes > 64U * 1024U * 1024U || parsed.blocks_.empty() ||
      parsed.blocks_.size() > cap.max_blocks) return error("native block/transaction limit exceeded");

  try {
  // ParsedBlock.blocks_ is ONLY a parser result; it is not independently a
  // first-included certificate. Check every original diff entry in exactly the
  // same order, including empty blocks. Never consult repeating current tips.
  const auto& diff = parsed.mc_block_.shard_blocks_diff_;
  if (diff.size() != parsed.blocks_.size())
    return error("parsed blocks do not cover first-included diff exactly");
  std::vector<BlockId> parsed_ids;
  std::vector<BlockId> diff_ids;
  parsed_ids.reserve(diff.size());
  diff_ids.reserve(diff.size());
  size_t boc_bytes = 0;
  for (size_t i = 0; i < diff.size(); ++i) {
    const auto& entry = diff[i];
    if (entry.block_data.is_null() || !entry.handle ||
        entry.handle->id() != entry.block_data->block_id())
      return error("missing diff block data or full handle ID mismatch");
    const auto id = entry.block_data->block_id();
    parsed_ids.push_back(block_id(parsed.blocks_[i]));
    diff_ids.push_back(block_id(id));
    if (!valid_base64_hash(diff_ids.back().root_hash) ||
        !valid_base64_hash(diff_ids.back().file_hash))
      return error("invalid original diff block hash");
    // file_hash() echoes metadata; hash the ORIGINAL BoC, not the echoed hash.
    const auto bytes = entry.block_data->data();
    if (bytes.empty() || bytes.size() > cap.max_provenance_bytes - boc_bytes ||
        td::sha256_bits256(bytes.as_slice()) != id.file_hash)
      return error("original diff BoC SHA-256 differs from full ID or exceeds cap");
    boc_bytes += bytes.size();
    const auto root = entry.block_data->root_cell();
    if (root.is_null() || root->get_hash().as_bits256() != id.root_hash)
      return error("original diff root cell differs from full ID");
  }
  if (!same_ordered_diff(parsed_ids, diff_ids, request.mc_block))
    return error("missing, extra, reordered or replaced diff block");

  std::set<std::string> addresses(request.item_addresses.begin(), request.item_addresses.end());
  std::map<std::string, BlockId> coordinates;
  std::vector<BlockId> included_blocks;
  included_blocks.reserve(parsed.blocks_.size());
  std::vector<Tx> transactions;
  size_t total_messages = 0;
  bool found_mc = false;
  for (const auto& block : parsed.blocks_) {
    auto id = block_id(block);
    if (!id.seqno || !valid_base64_hash(id.root_hash) || !valid_base64_hash(id.file_hash) ||
        !block.mc_block_workchain || *block.mc_block_workchain != -1 ||
        !block.mc_block_shard || *block.mc_block_shard != std::numeric_limits<int64_t>::min() ||
        !block.mc_block_seqno || *block.mc_block_seqno != request.mc_block.seqno)
      return error("missing or mismatched first-included block provenance");
    // Bound the LT/time interval to the raw block cell, not a mutable schema
    // metadata echo. The raw root was hash-checked against this exact diff ID.
    block::gen::Block::Record raw_block;
    block::gen::BlockInfo::Record raw_info;
    const auto raw_root = diff[included_blocks.size()].block_data->root_cell();
    if (!tlb::unpack_cell(raw_root, raw_block) ||
        !tlb::unpack_cell(raw_block.info, raw_info) ||
        raw_info.seq_no != block.seqno || raw_info.not_master != (block.workchain != -1) ||
        raw_info.start_lt != block.start_lt || raw_info.end_lt != block.end_lt ||
        raw_info.gen_utime != block.gen_utime || raw_block.global_id != block.global_id)
      return error("source block time/LT or identity differs from raw block cell");
    std::string key = std::to_string(id.workchain) + ":" + std::to_string(id.shard) +
                      ":" + std::to_string(id.seqno);
    if (!coordinates.emplace(key, id).second)
      return error("duplicate or conflicting first-included block provenance");
    included_blocks.push_back(id);
    if (id.workchain == -1) {
      if (id.shard != std::numeric_limits<int64_t>::min() || id.seqno != request.mc_block.seqno ||
          id.root_hash != request.mc_block.root_hash || id.file_hash != request.mc_block.file_hash)
        return error("MC full block ID mismatch");
      found_mc = true;
    }
    if (block.transactions.size() > cap.max_transactions - transactions.size())
      return error("native transaction limit exceeded");
    for (const auto& source : block.transactions) {
      if (source.account.workchain != id.workchain || source.raw.is_null() ||
          source.raw->get_hash().as_bits256() != source.hash ||
          !tx_within_source_block(source.lt, source.now, block.start_lt, block.end_lt, block.gen_utime))
        return error("raw transaction hash, account, LT or time differs from source block");
      size_t n = source.out_msgs.size() + static_cast<size_t>(source.in_msg.has_value());
      if (source.out_msgs.size() > cap.max_messages_per_tx ||
          n > cap.max_total_messages - total_messages)
        return error("native message limit exceeded");
      total_messages += n;
      Tx tx;
      tx.block = id;
      auto account_address = address(source.account);
      if (!account_address) return error("invalid account address hex from parsed transaction");
      tx.item_address = std::move(*account_address);
      tx.hash = source.hash.to_hex();
      tx.lt = source.lt;
      tx.now = source.now;
      tx.mc_seqno = source.mc_seqno;
      tx.state_hash_before = source.account_state_hash_before.to_hex();
      tx.state_hash_after = source.account_state_hash_after.to_hex();
      tx.was_active = source.orig_status == schema::active;
      tx.is_active = source.end_status == schema::active;
      tx.aborted = aborted(source);
      // No current-state/getter fallback, no expiry guess: ONLY tx evidence.
      if (addresses.count(tx.item_address)) {
        if (source.in_msg) tx.incoming = message(*source.in_msg);
        tx.outgoing.reserve(source.out_msgs.size());
        for (const auto& m : source.out_msgs) tx.outgoing.push_back(message(m));
      }
      transactions.push_back(std::move(tx));
    }
  }
  if (!found_mc) return error("MC block missing from first-included manifest");
  return extract_from_first_included(transactions, request, included_blocks);
  } catch (const vm::VmError&) {
    return error("raw diff block or transaction cell verification failed");
  }
}

}  // namespace assets_analytics::dns
