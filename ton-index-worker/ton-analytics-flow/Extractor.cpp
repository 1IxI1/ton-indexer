#include "Extractor.h"

#include "common/global-version.h"
#include "crypto/block/block-auto.h"
#include "crypto/block/block-parse.h"
#include "crypto/block/block.h"
#include "crypto/vm/dict.h"

#include <set>
#include <stdexcept>
#include <tuple>
#include <utility>

namespace ton_analytics::flow {
namespace {

using Coins = td::RefInt256;

[[noreturn]] void fail(const char* reason) { throw std::runtime_error(reason); }

Coins currency(td::Ref<vm::CellSlice> slice) {
  if (slice.is_null()) fail("missing CurrencyCollection");
  Coins coins;
  td::Ref<vm::Cell> other;
  if (!block::unpack_CurrencyCollection(slice, coins, other) || coins.is_null() || !coins->is_valid())
    fail("invalid CurrencyCollection");
  return coins;
}

Coins currency(const td::Ref<vm::Cell>& cell) {
  if (cell.is_null()) fail("missing CurrencyCollection cell");
  return currency(vm::load_cell_slice_ref(cell));
}

Coins grams(td::Ref<vm::CellSlice> slice) {
  if (slice.is_null()) fail("missing Grams");
  auto value = block::tlb::t_Grams.as_integer_skip(slice.write());
  if (value.is_null() || !value->is_valid()) fail("invalid Grams");
  return value;
}

BlockId id_of(const schema::BlockDataState& entry) {
  if (!entry.handle || entry.block_data.is_null() || entry.block_data->root_cell().is_null())
    fail("missing block handle or raw root");
  const auto& id = entry.handle->id();
  if (entry.block_data->block_id() != id ||
      !entry.block_data->root_cell()->get_hash().bits().equals(id.root_hash.bits(), 256))
    fail("block handle, data ID and raw root disagree");
  return {id.id.workchain, id.id.shard, id.id.seqno, id.root_hash.to_hex(), id.file_hash.to_hex()};
}

// Message Any: validate the entire TL-B type, not just the address prefix.
void inspect_message(const td::Ref<vm::Cell>& cell, const BlockId& block_id,
                     const block::gen::Transaction::Record& tx, uint16_t index,
                     Batch& batch, BlockFact& fact, Coins& sink_sum, const Limits& limits) {
  if (cell.is_null()) fail("missing out-message cell");
  block::gen::Message::Record msg;
  if (!tlb::type_unpack_cell(cell, block::gen::t_Message_Any, msg)) fail("invalid out-message TL-B");
  const auto tag = block::gen::CommonMsgInfo().get_tag(*msg.info);
  if (tag == block::gen::CommonMsgInfo::ext_out_msg_info) return;
  if (tag != block::gen::CommonMsgInfo::int_msg_info) fail("invalid outgoing message type");
  block::gen::CommonMsgInfo::Record_int_msg_info info;
  if (!tlb::csr_unpack(msg.info, info)) fail("invalid internal message info");
  block::StdAddress address;
  block::StdAddress effective;
  if (!block::tlb::t_MsgAddressInt.extract_std_address(info.dest, address, false) ||
      !block::tlb::t_MsgAddressInt.extract_std_address(info.dest, effective, true))
    fail("cannot normalize internal message destination");
  auto value = currency(info.value);
  if (address.workchain != 0 || address.addr != td::Bits256::zero() ||
      effective.workchain != 0 || effective.addr != td::Bits256::zero()) return;
  detail::record_zero_sink_send(batch, fact,
                                {block_id, tx.account_addr.to_hex(), tx.lt,
                                 "", index, cell->get_hash().to_hex(), tx.now,
                                 value->to_dec_string(), info.bounce, info.bounced},
                                value, sink_sum, limits.max_zero_sink_sends_per_batch);
}

Coins transactions(const td::Ref<vm::Cell>& root, Batch& batch, BlockFact& fact,
                  const Limits& limits) {
  vm::AugmentedDictionary accounts{vm::load_cell_slice_ref(root), 256,
                                    block::tlb::aug_ShardAccountBlocks};
  auto extra = accounts.get_root_extra();
  if (extra.is_null()) fail("missing account-block fee augmentation");
  auto account_fees = currency(extra);
  fact.tx_fee_augmentation_nanoton = account_fees->to_dec_string();
  auto sink_sum = td::make_refint(0);
  size_t messages_seen = 0;
  size_t account_count = 0;
  bool ok = accounts.validate_check_extra([&](td::Ref<vm::CellSlice> value,
                                               td::Ref<vm::CellSlice>, td::ConstBitPtr key, int bits) {
    if (++account_count > limits.max_accounts_per_block || bits != 256) return false;
    block::gen::AccountBlock::Record account;
    if (value.is_null() || !tlb::csr_unpack(value, account) ||
        !key.equals(account.account_addr.bits(), 256)) return false;
    vm::AugmentedDictionary txs{vm::DictNonEmpty(), account.transactions, 64,
                                 block::tlb::aug_AccountTransactions};
    return txs.validate_check_extra([&](td::Ref<vm::CellSlice> tx_value,
                                         td::Ref<vm::CellSlice>, td::ConstBitPtr tx_key, int tx_bits) {
      if (fact.tx_count >= limits.max_transactions_per_block || tx_bits != 64 || tx_value.is_null() ||
          tx_value->size() != 0 || tx_value->size_refs() != 1) return false;
      auto tx_cell = tx_value->prefetch_ref();
      block::gen::Transaction::Record tx;
      if (tx_cell.is_null() || !tlb::unpack_cell(tx_cell, tx) ||
          tx.account_addr != account.account_addr ||
          td::bitstring::bits_load_ulong(tx_key, 64) != tx.lt ||
          tx.now != fact.gen_utime || tx.outmsg_cnt < 0 || tx.outmsg_cnt > 32767) return false;
      detail::count_transaction(fact, limits.max_transactions_per_block);
      if (static_cast<size_t>(tx.outmsg_cnt) > limits.max_messages_per_block - messages_seen)
        return false;
      messages_seen += tx.outmsg_cnt;
      vm::Dictionary outs{tx.r1.out_msgs, 15};
      int count = 0;
      const size_t first_send = batch.zero_sink_sends.size();
      if (!outs.check_for_each([&](td::Ref<vm::CellSlice> message, td::ConstBitPtr index, int len) {
            if (len != 15 || message.is_null() || message->size() != 0 || message->size_refs() != 1 ||
                count >= tx.outmsg_cnt) return false;
            unsigned key_value = 0;
            for (int i = 0; i < 15; ++i) key_value = (key_value << 1) | index[i];
            if (key_value != static_cast<unsigned>(count)) return false;
            inspect_message(message->prefetch_ref(), fact.id, tx, static_cast<uint16_t>(count),
                            batch, fact, sink_sum, limits);
            ++count;
            return true;
          }) || count != tx.outmsg_cnt) return false;
      // Message identity is (source block, tx account/LT/hash, out-msg index),
      // never only the message hash (identical cells may occur twice).
      for (size_t n = first_send; n < batch.zero_sink_sends.size(); ++n)
        batch.zero_sink_sends[n].tx_hash = tx_cell->get_hash().to_hex();
      return true;
    });
  });
  if (!ok) fail("invalid or oversized AccountBlocks/transactions/out-messages");
  return account_fees;
}

} // namespace

namespace detail {

uint32_t require_applied_global_version(const AppliedGlobalVersion& resolve,
                                        const BlockId& block) {
  if (!resolve) fail("missing historical global version resolver");
  auto version = resolve(block);
  if (!version || *version > static_cast<uint32_t>(ton::SUPPORTED_VERSION))
    fail("missing or unsupported historical global version for raw block");
  return *version;
}

void count_transaction(BlockFact& fact, size_t max_transactions) {
  if (fact.tx_count >= max_transactions) fail("transaction count limit exceeded");
  ++fact.tx_count;
}

void record_zero_sink_send(Batch& batch, BlockFact& fact, ZeroSinkSend send,
                           td::RefInt256 value, td::RefInt256& block_sum,
                           size_t max_batch_sends) {
  if (value.is_null() || !value->is_valid() || value < 0 ||
      send.value_nanoton != value->to_dec_string()) fail("invalid synthetic/send amount");
  if (block_sum.is_null() || !block_sum->is_valid()) fail("invalid block sink sum");
  if (batch.zero_sink_sends.size() >= max_batch_sends) fail("zero sink send limit exceeded");
  auto next = block_sum + value;
  if (next.is_null() || !next->is_valid()) fail("sink sum overflow");
  batch.zero_sink_sends.push_back(std::move(send));
  block_sum = std::move(next);
  ++fact.zero_sink_sent_count;
  fact.zero_sink_sent_nanoton = block_sum->to_dec_string();
}

} // namespace detail

Batch extract(const schema::MasterchainBlockDataState& source,
              const AppliedGlobalVersion& applied_version, const Limits& limits) {
  try {
  if (source.shard_blocks_diff_.empty() || source.shard_blocks_diff_.size() > limits.max_blocks)
    fail("missing or oversized first-inclusion block set");
  if (!applied_version) fail("missing historical global version resolver");
  Batch batch;
  std::set<std::tuple<int32_t, uint64_t, uint32_t>> coordinates;
  for (const auto& entry : source.shard_blocks_diff_) {
    auto id = id_of(entry);
    if (!coordinates.emplace(id.workchain, id.shard, id.seqno).second)
      fail("duplicate block coordinate in first-inclusion set");
    const uint32_t version = detail::require_applied_global_version(applied_version, id);
    block::gen::Block::Record raw;
    block::gen::BlockInfo::Record info;
    if (!tlb::unpack_cell(entry.block_data->root_cell(), raw) || !tlb::unpack_cell(raw.info, info) ||
        info.seq_no != id.seqno || (info.not_master == (id.workchain == -1)))
      fail("invalid Block/BlockInfo or block ID mismatch");
    if (info.shard.is_null() || raw.value_flow.is_null() || raw.extra.is_null())
      fail("missing BlockInfo shard, ValueFlow or BlockExtra");
    block::ShardId shard(info.shard);
    if (!shard.is_valid() || shard.workchain_id != id.workchain || shard.shard_pfx != id.shard)
      fail("BlockInfo shard differs from full block ID");
    if (id.workchain == -1) {
      if (!batch.blocks.empty() || !batch.mc_id.root_hash.empty()) fail("MC must occur once and first");
      batch.mc_id = id;
      batch.mc_gen_utime = info.gen_utime;
    } else if (batch.mc_id.root_hash.empty()) fail("first-inclusion set lacks MC anchor");

    BlockFact fact{};
    fact.id = id;
    fact.applied_global_version = version;
    fact.gen_utime = info.gen_utime;
    fact.raw_root_hash = entry.block_data->root_cell()->get_hash().to_hex();
    fact.zero_sink_sent_nanoton = "0";
    const auto tag = vm::load_cell_slice(raw.value_flow).prefetch_ulong(32);
    if (tag == 0x3ebf98b7) {
      block::gen::ValueFlow::Record_value_flow_v2 flow;
      if (!tlb::unpack_cell(raw.value_flow, flow)) fail("invalid ValueFlow v2");
      fact.created_nanoton = currency(flow.r2.created)->to_dec_string();
      fact.burned_nanoton = currency(flow.burned)->to_dec_string();
      fact.minted_grams_nanoton = currency(flow.r2.minted)->to_dec_string();
      fact.burn_status = "total_from_v2_breakdown_unknown";
    } else if (tag == 0xb8e48dfb) {
      block::gen::ValueFlow::Record_value_flow flow;
      if (!tlb::unpack_cell(raw.value_flow, flow)) fail("invalid ValueFlow v1");
      fact.created_nanoton = currency(flow.r2.created)->to_dec_string();
      fact.minted_grams_nanoton = currency(flow.r2.minted)->to_dec_string();
      fact.burn_status = "value_flow_v1_absent";
    } else fail("unknown ValueFlow constructor");
    block::gen::BlockExtra::Record extra;
    if (!tlb::unpack_cell(raw.extra, extra) || extra.account_blocks.is_null() ||
        extra.in_msg_descr.is_null()) fail("missing or invalid BlockExtra roots");
    block::tlb::Aug_InMsgDescr in_augmentation(static_cast<int>(version));
    vm::AugmentedDictionary incoming{vm::load_cell_slice_ref(extra.in_msg_descr), 256,
                                      in_augmentation};
    auto import = incoming.get_root_extra();
    if (import.is_null()) fail("missing import fee augmentation");
    size_t incoming_count = 0;
    if (!incoming.validate_check_extra([&](td::Ref<vm::CellSlice>, td::Ref<vm::CellSlice>,
                                            td::ConstBitPtr, int bits) {
          return bits == 256 && ++incoming_count <= limits.max_messages_per_block;
        })) fail("invalid or oversized incoming message fee dictionary");
    auto import_coins = grams(import);
    fact.import_fee_augmentation_nanoton = import_coins->to_dec_string();
    auto fees = transactions(extra.account_blocks, batch, fact, limits);
    fees += import_coins;
    if (!fees->is_valid()) fail("gross fee overflow");
    fact.gross_fees_nanoton = fees->to_dec_string();
    batch.blocks.push_back(std::move(fact));
  }
  for (auto& fact : batch.blocks) {
    fact.first_included_by = batch.mc_id;
    fact.mc_inclusion_utime = batch.mc_gen_utime;
  }
  return batch;
  } catch (const vm::VmError& error) {
    throw std::runtime_error(std::string("TON dictionary/cell decode: ") + error.get_msg());
  }
}

} // namespace ton_analytics::flow
