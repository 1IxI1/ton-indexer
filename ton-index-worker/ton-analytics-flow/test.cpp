#include "Extractor.h"

#include "crypto/block/block-parse.h"
#include "crypto/vm/cells/CellBuilder.h"

#include <stdexcept>
#include <utility>

using namespace ton_analytics::flow;

int main() {
  const AppliedGlobalVersion version = [](const BlockId&) { return std::optional<uint32_t>{11}; };
  schema::MasterchainBlockDataState empty;
  bool rejected = false;
  try { (void)extract(empty, version); } catch (const std::runtime_error&) { rejected = true; }
  if (!rejected) return 1;

  // A diff with a missing raw root/handle must not silently publish zero.
  empty.shard_blocks_diff_.emplace_back();
  rejected = false;
  try { (void)extract(empty, {}); } catch (const std::runtime_error&) { rejected = true; }
  if (!rejected) return 2;

  rejected = false;
  try { (void)extract(empty, version); } catch (const std::runtime_error&) { rejected = true; }
  if (!rejected) return 3;

  Limits zero;
  zero.max_blocks = 0;
  rejected = false;
  try { (void)extract(empty, version, zero); } catch (const std::runtime_error&) { rejected = true; }
  if (!rejected) return 4;

  BlockId mc{-1, 0x8000000000000000ULL, 42, "mc", "mc-file"};
  BlockId shard{0, 0x8000000000000000ULL, 99, "shard", "shard-file"};
  AppliedGlobalVersion per_block = [](const BlockId& id) -> std::optional<uint32_t> {
    return id.workchain == -1 ? 12 : 11;
  };
  if (detail::require_applied_global_version(per_block, mc) != 12 ||
      detail::require_applied_global_version(per_block, shard) != 11) return 11;
  rejected = false;
  try {
    (void)detail::require_applied_global_version(
        [](const BlockId&) -> std::optional<uint32_t> { return std::nullopt; }, shard);
  } catch (const std::runtime_error&) { rejected = true; }
  if (!rejected) return 12;
  rejected = false;
  try {
    (void)detail::require_applied_global_version(
        [](const BlockId&) -> std::optional<uint32_t> { return 999; }, shard);
  } catch (const std::runtime_error&) { rejected = true; }
  if (!rejected) return 13;

  // Positive synthetic observations: zero and one transaction, two sends of
  // even the SAME message hash remain distinct by out_msg_index.
  BlockFact fact{};
  Batch batch{};
  fact.zero_sink_sent_nanoton = "0";
  if (fact.tx_count != 0 || fact.zero_sink_sent_count != 0) return 5;
  detail::count_transaction(fact, 1);
  if (fact.tx_count != 1) return 6;
  rejected = false;
  try { detail::count_transaction(fact, 1); } catch (const std::runtime_error&) { rejected = true; }
  if (!rejected) return 7;
  auto sum = td::make_refint(0);
  ZeroSinkSend first{};
  first.out_msg_index = 0;
  first.message_hash = "same-cell-hash";
  first.value_nanoton = "11";
  detail::record_zero_sink_send(batch, fact, first, td::make_refint(11), sum, 2);
  auto second = first;
  second.out_msg_index = 1;
  second.value_nanoton = "17";
  detail::record_zero_sink_send(batch, fact, second, td::make_refint(17), sum, 2);
  if (fact.zero_sink_sent_count != 2 || fact.zero_sink_sent_nanoton != "28" ||
      batch.zero_sink_sends.size() != 2 || batch.zero_sink_sends[0].out_msg_index != 0 ||
      batch.zero_sink_sends[1].out_msg_index != 1 || sum->to_dec_string() != "28") return 8;
  rejected = false;
  try { detail::record_zero_sink_send(batch, fact, second, td::make_refint(17), sum, 2); }
  catch (const std::runtime_error&) { rejected = true; }
  if (!rejected || batch.zero_sink_sends.size() != 2 || fact.zero_sink_sent_count != 2) return 14;

  // Pre-v12 IHR regression for TON's native augmentation calculation, not a
  // full valid block fixture. ImportFees.value_imported includes extra_flags
  // (legacy ihr_fee=7) at v11 and excludes it at v12.
  vm::CellBuilder msg;
  msg.store_long(0, 4); // int_msg_info$0 + ihr_disabled/bounce/bounced flags
  for (int i = 0; i != 2; ++i) {
    msg.store_long(4, 3).store_zeroes(8 + 256); // addr_std$10, no anycast, wc 0, addr 0
  }
  msg.store_long(1, 4).store_long(1, 8).store_long(0, 1); // value 1, empty extras
  msg.store_long(1, 4).store_long(7, 8); // legacy IHR (extra_flags)
  msg.store_long(0, 4).store_zeroes(64 + 32); // fwd fee 0, created_lt/at
  msg.store_long(0, 2); // no StateInit; inline empty body
  auto message = msg.finalize();
  vm::CellBuilder envelope;
  envelope.store_long(4, 4).store_zeroes(16).store_long(1, 4).store_long(3, 8);
  envelope.store_ref(std::move(message)); // msg_envelope#4; two regular intermediate addrs
  auto envelope_cell = envelope.finalize();
  vm::CellBuilder in_msg;
  in_msg.store_long(4, 3).store_ref(envelope_cell).store_ref(vm::CellBuilder().finalize());
  in_msg.store_long(1, 4).store_long(3, 8); // msg_import_fin, fwd_fee=3
  auto incoming = in_msg.finalize();
  for (const auto [version_number, expected_imported] :
       {std::pair{11, 11}, std::pair{12, 4}}) {
    block::tlb::Aug_InMsgDescr augmentation(version_number);
    vm::CellBuilder result;
    auto slice = vm::load_cell_slice(incoming);
    if (!augmentation.eval_leaf(result, slice)) return 9;
    auto result_slice = vm::load_cell_slice(result.finalize());
    auto fees = block::tlb::t_Grams.as_integer_skip(result_slice);
    td::RefInt256 imported;
    td::Ref<vm::Cell> other;
    if (fees.is_null() || fees->to_dec_string() != "3" ||
        !block::unpack_CurrencyCollection(vm::load_cell_slice_ref(
                                               vm::CellBuilder().append_cellslice(result_slice).finalize()),
                                           imported, other) ||
        imported.is_null() || imported->to_dec_string() != std::to_string(expected_imported)) return 10;
  }
}
