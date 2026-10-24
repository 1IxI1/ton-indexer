#include "WalletRawInventory.h"

#include "crypto/block/block-auto.h"
#include "crypto/vm/boc.h"
#include "crypto/vm/cells/DataCell.h"
#include "crypto/vm/dict.h"
#include "common/checksum.h"
#include "td/utils/crypto.h"
#include "validator/impl/block.hpp"

#include <source_location>
#include <stdexcept>
#include <tuple>
#include <vector>

namespace {
using Cell = td::Ref<vm::Cell>;

// Only id() is read by the inventory. This inert handle makes an actual
// BlockDataState possible without linking a validator/scanner implementation.
struct MemoryHandle final : ton::validator::BlockHandleInterface {
  ton::BlockIdExt block;
  explicit MemoryHandle(ton::BlockIdExt id) : block(id) {}
  ton::BlockIdExt id() const override { return block; }
#define RAW_FALSE(name) bool name() const override { return false; }
  RAW_FALSE(received) RAW_FALSE(moved_to_archive) RAW_FALSE(handle_moved_to_archive)
  RAW_FALSE(deleted) RAW_FALSE(inited_next_left) RAW_FALSE(inited_next_right)
  RAW_FALSE(inited_next) RAW_FALSE(inited_prev_left) RAW_FALSE(inited_prev_right)
  RAW_FALSE(inited_prev) RAW_FALSE(inited_logical_time) RAW_FALSE(inited_unix_time)
  RAW_FALSE(inited_proof) RAW_FALSE(inited_proof_link) RAW_FALSE(inited_signatures)
  RAW_FALSE(inited_split_after) RAW_FALSE(inited_merge_before) RAW_FALSE(inited_is_key_block)
  RAW_FALSE(inited_masterchain_ref_block) RAW_FALSE(split_after) RAW_FALSE(merge_before)
  RAW_FALSE(is_key_block) RAW_FALSE(inited_state_root_hash) RAW_FALSE(received_state)
  RAW_FALSE(inited_state_boc) RAW_FALSE(deleted_state_boc) RAW_FALSE(need_flush)
  RAW_FALSE(is_zero) RAW_FALSE(is_applied) RAW_FALSE(processed) RAW_FALSE(applied_stored)
#undef RAW_FALSE
  ton::BlockSeqno masterchain_ref_block() const override { return 0; }
  std::vector<ton::BlockIdExt> prev() const override { return {}; }
  ton::BlockIdExt one_prev(bool) const override { return {}; }
  std::vector<ton::BlockIdExt> next() const override { return {}; }
  ton::BlockIdExt one_next(bool) const override { return {}; }
  ton::RootHash state() const override { return {}; }
  td::uint32 version() const override { return 0; }
  void flush(td::actor::ActorId<ton::validator::ValidatorManagerInterface>,
             std::shared_ptr<ton::validator::BlockHandleInterface>, td::Promise<td::Unit>) override {
    throw std::runtime_error("synthetic handle has no manager");
  }
  td::actor::Task<> flush(td::actor::ActorId<ton::validator::ValidatorManagerInterface>,
                          std::shared_ptr<ton::validator::BlockHandleInterface>) override {
    throw std::runtime_error("synthetic handle has no manager");
  }
  void flushed_upto(td::uint32) override {}
  void set_logical_time(ton::LogicalTime) override {}
  void set_unix_time(ton::UnixTime) override {}
  ton::LogicalTime logical_time() const override { return 0; }
  ton::UnixTime unix_time() const override { return 0; }
#define RAW_NOP(name) void name() override {}
  RAW_NOP(set_processed) RAW_NOP(set_applied_stored) RAW_NOP(set_proof) RAW_NOP(set_proof_link)
  RAW_NOP(set_signatures) RAW_NOP(set_received) RAW_NOP(set_moved_to_archive)
  RAW_NOP(set_handle_moved_to_archive) RAW_NOP(set_deleted) RAW_NOP(set_state_boc)
  RAW_NOP(set_deleted_state_boc) RAW_NOP(set_applied)
  RAW_NOP(unsafe_clear_applied) RAW_NOP(unsafe_clear_next)
#undef RAW_NOP
  void set_next(ton::BlockIdExt) override {}
  void set_prev(ton::BlockIdExt) override {}
  void set_split(bool) override {}
  void set_merge(bool) override {}
  void set_is_key_block(bool) override {}
  void set_state_root_hash(ton::RootHash) override {}
  void set_masterchain_ref_block(ton::BlockSeqno) override {}
  td::BufferSlice serialize() const override { return {}; }
};

void check(bool ok, std::source_location from = std::source_location::current()) {
  if (!ok) throw std::runtime_error("raw inventory assertion at line " + std::to_string(from.line()));
}

td::Bits256 number(unsigned n) {
  td::Bits256 value = td::Bits256::zero();
  std::string hex(64, '0');
  hex[63] = "0123456789abcdef"[n & 15];
  check(value.from_hex(td::Slice(hex)));
  return value;
}

Cell finish(vm::CellBuilder& b) { return b.finalize(); }

void address(vm::CellBuilder& b, td::Bits256 who) {
  check(b.store_long_bool(4, 3) && b.store_long_bool(0, 8) && b.store_bits_bool(who));
}

Cell message(bool external, bool bounced, bool matching, Cell body = {}) {
  vm::CellBuilder b;
  check(b.store_long_bool(external ? 3 : 0, external ? 2 : 1));
  if (!external) check(b.store_long_bool(1, 1) && b.store_long_bool(1, 1) &&
                       b.store_long_bool(bounced, 1)); // bounce=true even for normal send
  address(b, number(matching ? 1 : 2));
  if (external) check(b.store_long_bool(0, 2)); // destination addr_none (external)
  else {
    address(b, number(3));
    check(b.store_long_bool(0, 5) && b.store_long_bool(0, 4) && b.store_long_bool(0, 4));
  }
  check(b.store_long_bool(99, 64) && b.store_long_bool(100, 32) &&
        b.store_long_bool(0, 1) && b.store_long_bool(body.not_null(), 1)); // no StateInit
  if (body.not_null()) check(b.store_ref_bool(body));
  return finish(b);
}

Cell incoming_external() {
  vm::CellBuilder b;
  check(b.store_long_bool(2, 2) && b.store_long_bool(0, 2)); // ext-in; source addr_none
  address(b, number(1));
  check(b.store_long_bool(0, 4) && b.store_long_bool(0, 1) && b.store_long_bool(0, 1));
  return finish(b);
}

// One full-key HashmapAug leaf. Augmentation = zero CurrencyCollection;
// account and tx augmented values have independent, matching zero fees.
void long_label(vm::CellBuilder& b, unsigned width, unsigned bits, td::ConstBitPtr key) {
  check(b.store_long_bool(2, 2) && b.store_long_bool(bits, width) && b.store_bits_bool(key, bits));
}

Cell transaction_description(unsigned messages) {
  vm::CellBuilder gas;
  check(gas.store_long_bool(0, 3) && gas.store_long_bool(0, 3) && gas.store_long_bool(0, 1) &&
        gas.store_long_bool(0, 8) && gas.store_long_bool(0, 32) && gas.store_long_bool(0, 1) &&
        gas.store_long_bool(1, 32) && gas.store_bits_bool(number(0)) && gas.store_bits_bool(number(0)));
  vm::CellBuilder action;
  check(action.store_long_bool(1, 1) && action.store_long_bool(1, 1) && action.store_long_bool(0, 1) &&
        action.store_long_bool(0, 1) && action.store_long_bool(0, 1) && action.store_long_bool(0, 1) &&
        action.store_long_bool(0, 32) && action.store_long_bool(0, 1) && action.store_long_bool(messages, 16) &&
        action.store_long_bool(0, 16) && action.store_long_bool(0, 16) && action.store_long_bool(messages, 16) &&
        action.store_bits_bool(number(0)) && action.store_long_bool(0, 3) && action.store_long_bool(0, 3));
  vm::CellBuilder desc;
  check(desc.store_long_bool(0, 4) && desc.store_long_bool(0, 3) && // ordinary, no storage/credit
        desc.store_long_bool(1, 1) && desc.store_long_bool(1, 1) && desc.store_long_bool(0, 1) &&
        desc.store_long_bool(1, 1) && desc.store_long_bool(0, 4) && desc.store_ref_bool(finish(gas)) &&
        desc.store_long_bool(1, 1) && desc.store_ref_bool(finish(action)) && desc.store_long_bool(0, 3));
  auto result = finish(desc);
  check(block::gen::t_TransactionDescr.validate_ref(result));
  return result;
}

Cell empty_shard_state(unsigned seqno) {
  vm::CellBuilder queue, accounts, auxiliary, state;
  check(queue.store_long_bool(0, 1) && queue.store_long_bool(0, 64) && queue.store_long_bool(0, 2));
  check(accounts.store_long_bool(0, 11)); // empty HashmapAugE + depth/balance augmentation
  check(auxiliary.store_long_bool(0, 64) && auxiliary.store_long_bool(0, 64) &&
        auxiliary.store_long_bool(0, 12)); // two balances, libraries, master_ref
  check(state.store_long_bool(0x9023afe2, 32) && state.store_long_bool(-3, 32) &&
        state.store_long_bool(0, 8) && state.store_long_bool(0, 32) &&
        state.store_long_bool(0x8000000000000000ULL, 64) && state.store_long_bool(seqno, 32) &&
        state.store_long_bool(0, 32) && state.store_long_bool(100, 32) && state.store_long_bool(100, 64) &&
        state.store_long_bool(0, 32) && state.store_ref_bool(finish(queue)) && state.store_long_bool(0, 1) &&
        state.store_ref_bool(finish(accounts)) && state.store_ref_bool(finish(auxiliary)) && state.store_long_bool(0, 1));
  auto result = finish(state);
  check(block::gen::t_ShardState.validate_ref(result));
  return result;
}

struct Fixture {
  schema::BlockDataState source;
  ton_analytics::wallets::raw_inventory::CallerProof proof;
  std::string transaction_hash;
};

struct MemoryBlock final : ton::validator::BlockData {
  ton::BlockIdExt id;
  Cell cell;
  td::BufferSlice bytes;
  MemoryBlock(ton::BlockIdExt id, Cell cell, td::BufferSlice bytes = {})
      : id(id), cell(std::move(cell)), bytes(std::move(bytes)) {}
  td::BufferSlice data() const override { return bytes.clone(); }
  ton::FileHash file_hash() const override { return id.file_hash; }
  ton::BlockIdExt block_id() const override { return id; }
  Cell root_cell() const override { return cell; }
};

Fixture fixture(std::vector<Cell> msgs, unsigned now = 100, unsigned long long dict_lt = 9,
                bool wrong_tx_addr = false, bool wrong_root_fees = false, bool complete_cells = true) {
  vm::Dictionary outs(15);
  for (unsigned n = 0; n < msgs.size(); ++n)
    check(outs.set_ref(td::BitArray<15>{static_cast<long long>(n)}, msgs[n]));
  if (!msgs.empty()) // A canonical dictionary cannot contain the same key twice.
    check(!outs.set_ref(td::BitArray<15>{0LL}, msgs.front(), vm::Dictionary::SetMode::Add));
  vm::CellBuilder auxiliary;
  check(auxiliary.store_long_bool(0, 1) && outs.append_dict_to_bool(auxiliary));
  auto aux = finish(auxiliary);

  vm::CellBuilder update;
  check(update.store_long_bool(0x72, 8) && update.store_bits_bool(number(4)) &&
        update.store_bits_bool(number(5)));
  auto hashes = finish(update);
  vm::CellBuilder tx;
  check(tx.store_long_bool(7, 4) && tx.store_bits_bool(number(wrong_tx_addr ? 2 : 1)) &&
        tx.store_long_bool(9, 64) && tx.store_bits_bool(number(0)) &&
        tx.store_long_bool(0, 64) && tx.store_long_bool(now, 32) &&
        tx.store_long_bool(msgs.size(), 15) && tx.store_long_bool(0, 2) &&
        tx.store_long_bool(2, 2) && tx.store_ref_bool(aux) &&
        tx.store_long_bool(0, 4) && tx.store_long_bool(0, 1) &&
        tx.store_ref_bool(hashes) && tx.store_ref_bool(transaction_description(msgs.size())));
  auto tx_cell = finish(tx);
  if (complete_cells) check(block::gen::t_Transaction.validate_ref(tx_cell));
  block::CurrencyCollection tx_fees;
  if (!block::tlb::t_Transaction.get_total_fees(vm::load_cell_slice(tx_cell), tx_fees))
    throw std::runtime_error("fixture transaction fees malformed");
  vm::CellBuilder tx_leaf;
  td::BitArray<64> tx_key{static_cast<long long>(dict_lt)};
  long_label(tx_leaf, 7, 64, tx_key.bits());
  check(tx_leaf.store_long_bool(0, 5) && tx_leaf.store_ref_bool(tx_cell));
  auto tx_root = finish(tx_leaf);
  // Duplicate (address,LT) cannot be serialized by a canonical HashmapAug:
  // native Add on the already occupied LT must fail before inventory parsing.
  vm::AugmentedDictionary duplicate_lt{tx_root, 64, block::tlb::aug_AccountTransactions};
  if (duplicate_lt.set_ref(tx_key, tx_cell, vm::AugmentedDictionary::SetMode::Add))
    throw std::runtime_error("duplicate LT accepted by native dictionary");

  vm::CellBuilder account;
  check(account.store_long_bool(5, 4) && account.store_bits_bool(number(1)) &&
        account.append_cellslice_bool(vm::load_cell_slice_ref(tx_root)) &&
        account.store_ref_bool(hashes));
  auto account_cell = finish(account);
  block::CurrencyCollection account_fees;
  if (!block::tlb::t_AccountBlock.get_total_fees(vm::load_cell_slice(account_cell), account_fees))
    throw std::runtime_error("fixture account fees malformed");
  vm::CellBuilder accounts_leaf;
  long_label(accounts_leaf, 9, 256, number(1).bits());
  check(accounts_leaf.store_long_bool(0, 5) &&
        accounts_leaf.append_cellslice_bool(vm::load_cell_slice_ref(account_cell)));
  auto leaf = finish(accounts_leaf);
  vm::AugmentedDictionary probe{leaf, 256, block::tlb::aug_ShardAccountBlocks};
  auto probe_extra = probe.get_root_extra();
  if (probe_extra.is_null()) throw std::runtime_error("fixture AccountBlocks leaf has no root augmentation");
  vm::CellBuilder expected_extra, actual_extra;
  check(expected_extra.store_long_bool(0, 5) && actual_extra.append_cellslice_bool(probe_extra));
  if (expected_extra.finalize()->get_hash() != actual_extra.finalize()->get_hash())
    throw std::runtime_error("fixture AccountBlocks leaf augmentation is not zero");
  vm::CellBuilder accounts;
  check(accounts.store_long_bool(1, 1) && accounts.store_ref_bool(leaf));
  if (wrong_root_fees) check(accounts.store_long_bool(1, 4) && accounts.store_long_bool(1, 8) &&
                              accounts.store_long_bool(0, 1)); // incorrect nonzero fee augmentation
  else check(accounts.store_long_bool(0, 5)); // correct zero CurrencyCollection

  vm::CellBuilder in_descr, out_descr;
  check(in_descr.store_long_bool(0, 10) && out_descr.store_long_bool(0, 6));
  vm::CellBuilder extra;
  check(extra.store_long_bool(0x4a33f6fd, 32) && extra.store_ref_bool(finish(in_descr)) &&
        extra.store_ref_bool(finish(out_descr)) && extra.store_ref_bool(finish(accounts)) &&
        extra.store_bits_bool(number(0)) && extra.store_bits_bool(number(0)) &&
        extra.store_long_bool(0, 1));
  vm::CellBuilder predecessor;
  check(predecessor.store_long_bool(0, 64) && predecessor.store_long_bool(6, 32) &&
        predecessor.store_bits_bool(number(0)) && predecessor.store_bits_bool(number(0)));
  auto previous = finish(predecessor);
  vm::CellBuilder info;
  check(info.store_long_bool(0x9bc7a987, 32) && info.store_long_bool(0, 32) &&
        info.store_long_bool(1, 1) && info.store_long_bool(0, 7) &&
        info.store_long_bool(0, 8) && info.store_long_bool(7, 32) &&
        info.store_long_bool(0, 32) && info.store_long_bool(0, 2) &&
        info.store_long_bool(0, 6) && info.store_long_bool(0, 32) &&
        info.store_long_bool(0x8000000000000000ULL, 64) && info.store_long_bool(100, 32) &&
        info.store_long_bool(0, 64) && info.store_long_bool(100, 64) &&
        info.store_long_bool(0, 32) && info.store_long_bool(0, 32) &&
        info.store_long_bool(0, 32) && info.store_long_bool(0, 32) &&
        info.store_ref_bool(previous) && info.store_ref_bool(previous)); // master_ref, prev_ref
  vm::CellBuilder amounts, flow;
  check(amounts.store_long_bool(0, 20));
  auto four_balances = finish(amounts);
  check(flow.store_long_bool(0xb8e48dfb, 32) && flow.store_ref_bool(four_balances) &&
        flow.store_long_bool(0, 5) && flow.store_ref_bool(four_balances));
  const auto post_state = empty_shard_state(7);
  const auto state_update = vm::CellBuilder::create_merkle_update(empty_shard_state(6), post_state);
  vm::CellBuilder block;
  check(block.store_long_bool(0x11ef55aa, 32) && block.store_long_bool(-3, 32) &&
        block.store_ref_bool(finish(info)) && block.store_ref_bool(finish(flow)) &&
        block.store_ref_bool(state_update) && block.store_ref_bool(finish(extra)));
  auto root = finish(block);
  if (complete_cells) check(block::gen::t_Block.validate_ref(root)); // TL-B, not a canonical execution proof
  const td::Bits256 hash(root->get_hash().bits());
  ton::BlockIdExt id{0, 0x8000000000000000ULL, 7, hash, hash};
  Fixture result;
  result.source.handle = std::make_shared<MemoryHandle>(id);
  result.source.block_data = td::Ref<MemoryBlock>{true, id, root};
  result.source.block_state = post_state;
  result.proof = {id, true, true, "synthetic-NOT-canonical"};
  result.transaction_hash = tx_cell->get_hash().to_hex();
  return result;
}

template <class Exception, class F> void rejects(F&& f) {
  bool rejected = false;
  try { f(); } catch (const Exception&) { rejected = true; }
  check(rejected);
}

template <class Exception, class F> void rejects_with(const std::string& reason, F&& f) {
  bool rejected = false;
  try { f(); } catch (const Exception& e) {
    check(std::string(e.what()).find(reason) != std::string::npos);
    rejected = true;
  }
  check(rejected);
}

// A sufficiently deep, valid Any body makes the native BoC serializer emit
// internal stored hashes. BlockQ then really leaves descendants lazy; no fake
// is_loaded() flag in the positive eager/lazy test.
Cell body_chain() {
  vm::CellBuilder empty;
  auto tail = finish(empty);
  for (unsigned n = 0; n < 180; ++n) {
    vm::CellBuilder b;
    check(b.store_long_bool(n, 32) && b.store_ref_bool(tail));
    tail = finish(b);
  }
  return tail;
}

Fixture backed(Fixture f, bool lazy) {
  auto root = f.source.block_data->root_cell();
  auto bytes = vm::std_boc_serialize(root, vm::BagOfCells::WithIndex | vm::BagOfCells::WithCRC32C |
                                            vm::BagOfCells::WithTopHash | vm::BagOfCells::WithIntHashes).move_as_ok();
  auto id = f.proof.expected_id;
  id.file_hash = td::sha256_bits256(bytes.as_slice());
  f.proof.expected_id = id;
  f.source.handle = std::make_shared<MemoryHandle>(id);
  if (lazy) f.source.block_data = ton::validator::BlockQ::create(id, std::move(bytes)).move_as_ok();
  else f.source.block_data = td::Ref<MemoryBlock>{true, id, root, std::move(bytes)};
  return f;
}

// Stop at unloaded cells: this assertion must not accidentally materialize the
// evidence whose laziness the regression is supposed to exercise.
Cell first_unloaded(Cell root) {
  std::vector<Cell> pending{std::move(root)};
  while (!pending.empty()) {
    auto cell = std::move(pending.back());
    pending.pop_back();
    if (!cell->is_loaded()) return cell;
    auto data = cell->load_cell().move_as_ok().data_cell;
    for (unsigned n = 0; n < data->get_refs_cnt(); ++n) pending.push_back(data->get_ref(n));
  }
  return {};
}

void same_facts(const ton_analytics::wallets::raw_inventory::Result& a,
                const ton_analytics::wallets::raw_inventory::Result& b) {
  const auto& x = a.inventory;
  const auto& y = b.inventory;
  check(std::tie(a.account_count, a.out_message_count, a.reachable_cell_references, a.caller_proof_id) ==
        std::tie(b.account_count, b.out_message_count, b.reachable_cell_references, b.caller_proof_id));
  check(std::tie(x.id.workchain, x.id.shard, x.id.seqno, x.id.root_hash, x.id.file_hash,
                 x.gen_utime, x.transactions_complete, x.statuses_complete, x.outgoing_complete) ==
        std::tie(y.id.workchain, y.id.shard, y.id.seqno, y.id.root_hash, y.id.file_hash,
                 y.gen_utime, y.transactions_complete, y.statuses_complete, y.outgoing_complete));
  check(x.transactions.size() == y.transactions.size());
  for (std::size_t n = 0; n < x.transactions.size(); ++n) {
    const auto& p = x.transactions[n];
    const auto& q = y.transactions[n];
    check(std::tie(p.account, p.lt, p.hash_hex, p.pre_state_hash_hex, p.post_state_hash_hex,
                   p.now, p.orig, p.end, p.first_qualifying_message_hash_hex) ==
          std::tie(q.account, q.lt, q.hash_hex, q.pre_state_hash_hex, q.post_state_hash_hex,
                   q.now, q.orig, q.end, q.first_qualifying_message_hash_hex));
  }
}

// Fault-injection only; native BlockQ/StaticBagOfCellsDbLazy above is the
// positive fixture. This preserves unloaded identity while returning bad data.
struct FaultCell final : vm::Cell {
  ::Cell identity;
  td::Ref<vm::DataCell> answer;
  unsigned* loads;
  FaultCell(::Cell identity, td::Ref<vm::DataCell> answer, unsigned* loads)
      : identity(std::move(identity)), answer(std::move(answer)), loads(loads) {}
  td::Status set_data_cell(td::Ref<vm::DataCell>&&) const override { return td::Status::Error("fault cell"); }
  td::Result<vm::LoadedCell> load_cell() const override { ++*loads; return vm::LoadedCell{answer, 0, {}}; }
  bool is_virtualized() const override { return false; }
  vm::CellUsageTree::NodePtr get_tree_node() const override { return {}; }
  bool is_loaded() const override { return false; }
  LevelMask get_level_mask() const override { return identity->get_level_mask(); }
  const Hash do_get_hash(td::uint32 level) const override { return identity->get_hash(level); }
  td::uint16 do_get_depth(td::uint32 level) const override { return identity->get_depth(level); }
};

void replace_root(Fixture& f, Cell root) {
  auto bytes = f.source.block_data->data();
  f.source.block_data = td::Ref<MemoryBlock>{true, f.proof.expected_id, std::move(root), std::move(bytes)};
}

void lazy_regressions() {
  namespace inv = ton_analytics::wallets::raw_inventory;
  const auto outgoing = message(false, false, true, body_chain());
  const auto original = fixture({message(false, true, true), outgoing, message(true, false, true)});
  const auto eager = backed(original, false);
  const auto lazy = backed(original, true);
  const auto lazy_cell = first_unloaded(lazy.source.block_data->root_cell());
  check(lazy_cell.not_null());
  const auto expected = inv::build(eager.source, eager.proof);
  const auto actual = inv::build(lazy.source, lazy.proof);
  same_facts(expected, actual);
  check(lazy_cell->is_loaded());
  // Keep the full positive tx/outgoing assertions, not just completion booleans.
  const auto& tx = actual.inventory.transactions.at(0);
  check(tx.hash_hex == original.transaction_hash && tx.lt == 9 && tx.now == 100 &&
        tx.account == std::string("0:") + number(1).to_hex() &&
        tx.orig == ton_analytics::wallets::AccountStatus::uninit &&
        tx.end == ton_analytics::wallets::AccountStatus::active &&
        tx.pre_state_hash_hex == number(4).to_hex() && tx.post_state_hash_hex == number(5).to_hex() &&
        tx.first_qualifying_message_hash_hex == outgoing->get_hash().to_hex());

  // Native weak-backed cell failure: deliberately drop BOTH the BlockQ and the
  // RootCell lease, retaining only its DataCell plus original bytes. The same
  // production helper must propagate the real expired-deserializer error.
  auto orphan = backed(original, true);
  auto orphan_root = orphan.source.block_data->root_cell()->load_cell().move_as_ok().data_cell;
  check(first_unloaded(orphan_root).not_null());
  replace_root(orphan, orphan_root);
  rejects_with<std::invalid_argument>("StaticBocDb is already destroyed", [&] {
    (void)inv::build(orphan.source, orphan.proof);
  });

  const auto capped = backed(original, true);
  const auto not_loaded = first_unloaded(capped.source.block_data->root_cell());
  auto bytes = capped.source.block_data->data();
  vm::BagOfCells::Info header;
  check(header.parse_serialized_header(bytes.as_slice()) > 0);
  inv::Limits limits;
  limits.max_cells = header.cell_count - 1;
  rejects_with<std::length_error>("backing BoC cell cap", [&] { (void)inv::build(capped.source, capped.proof, limits); });
  check(!not_loaded->is_loaded()); // backing cap checked BEFORE native expansion
  auto eager_no_bytes = eager; // exercise the independent repeated-edge cap
  eager_no_bytes.source.block_data = td::Ref<MemoryBlock>{true, eager.proof.expected_id,
                                                        eager.source.block_data->root_cell()};
  limits.max_cells = expected.reachable_cell_references;
  same_facts(expected, inv::build(eager_no_bytes.source, eager_no_bytes.proof, limits)); // inclusive boundary
  --limits.max_cells;
  rejects_with<std::length_error>("reachable-cell cap", [&] { (void)inv::build(eager_no_bytes.source, eager_no_bytes.proof, limits); });

  auto missing = eager;
  replace_root(missing, {});
  rejects_with<std::invalid_argument>("representation root hash", [&] { (void)inv::build(missing.source, missing.proof); });
  unsigned loads = 0;
  auto null_data = eager;
  replace_root(null_data, td::Ref<FaultCell>{true, eager.source.block_data->root_cell(), td::Ref<vm::DataCell>{}, &loads});
  rejects_with<std::invalid_argument>("loader returned null data", [&] { (void)inv::build(null_data.source, null_data.proof); });
  check(loads == 1);
  vm::CellBuilder empty;
  auto dummy = finish(empty);
  auto damaged = eager;
  replace_root(damaged, td::Ref<FaultCell>{true, eager.source.block_data->root_cell(),
                                         dummy->load_cell().move_as_ok().data_cell, &loads});
  rejects_with<std::invalid_argument>("loaded hash/depth/level mismatch", [&] { (void)inv::build(damaged.source, damaged.proof); });

  auto pruned = fixture({message(false, false, true, vm::CellBuilder::create_pruned_branch(body_chain(), 1))},
                        100, 9, false, false, false);
  rejects_with<std::invalid_argument>("pruned raw inventory cell", [&] { (void)inv::build(pruned.source, pruned.proof); });

  auto unavailable = backed(original, true);
  unavailable.source.block_data = td::Ref<MemoryBlock>{true, unavailable.proof.expected_id,
                                                      unavailable.source.block_data->root_cell()};
  rejects_with<std::invalid_argument>("original BoC unavailable", [&] {
    (void)inv::build(unavailable.source, unavailable.proof);
  });
  auto bad_bytes = eager.source.block_data->data().copy();
  bad_bytes.as_slice()[bad_bytes.size() - 1] ^= 1;
  auto corrupt = eager;
  corrupt.source.block_data = td::Ref<MemoryBlock>{true, eager.proof.expected_id,
                                                 eager.source.block_data->root_cell(), std::move(bad_bytes)};
  rejects_with<std::invalid_argument>("BoC file hash", [&] { (void)inv::build(corrupt.source, corrupt.proof); });

  // A loader behind state_update is NEVER invoked. This preserves the caller's
  // original root/full ID while making accidental shard-state traversal fail.
  auto ignored = eager;
  auto root_data = eager.source.block_data->root_cell()->load_cell().move_as_ok().data_cell;
  std::vector<Cell> refs;
  for (unsigned n = 0; n < root_data->get_refs_cnt(); ++n) refs.push_back(root_data->get_ref(n));
  loads = 0;
  refs[2] = td::Ref<FaultCell>{true, refs[2], td::Ref<vm::DataCell>{}, &loads};
  auto root = vm::DataCell::create(td::Slice(root_data->get_data(), (root_data->get_bits() + 7) / 8),
                                  root_data->get_bits(), refs, false).move_as_ok();
  check(root->get_hash() == eager.source.block_data->root_cell()->get_hash());
  replace_root(ignored, root);
  same_facts(expected, inv::build(ignored.source, ignored.proof));
  check(loads == 0);
}
} // namespace

// Compile/link with WalletRawInventory.cpp and the TON native libraries.
// In-memory TL-B cells with a synthetic block handle and caller proof: not a
// canonical file/state/inclusion proof. No network/NodeDB test is implied.
int main() {
  namespace inv = ton_analytics::wallets::raw_inventory;
  using ton_analytics::wallets::AccountStatus;
  lazy_regressions();
  check(inv::detail::status(block::gen::AccountStatus::acc_state_nonexist) == AccountStatus::nonexist);
  check(inv::detail::status(block::gen::AccountStatus::acc_state_uninit) == AccountStatus::uninit);
  check(inv::detail::status(block::gen::AccountStatus::acc_state_active) == AccountStatus::active);
  check(inv::detail::status(block::gen::AccountStatus::acc_state_frozen) == AccountStatus::frozen);
  bool rejected = false;
  try {
    (void)inv::detail::status(-1);
  } catch (const std::invalid_argument&) {
    rejected = true;
  }
  check(rejected);

  const auto a = message(false, false, true); // bounce=true, bounced=false
  const auto b = message(false, true, true);
  const auto c = message(true, false, true);
  const auto foreign = message(false, false, false);
  const auto first = fixture({b, foreign, a, c});
  const auto result = inv::build(first.source, first.proof);
  check(result.account_count == 1 && result.inventory.transactions.size() == 1 &&
        result.out_message_count == 4 && result.inventory.gen_utime == 100 &&
        result.inventory.id.workchain == 0 && result.inventory.id.seqno == 7 &&
        result.inventory.id.root_hash == first.proof.expected_id.root_hash.to_hex() &&
        result.inventory.id.file_hash == first.proof.expected_id.file_hash.to_hex() &&
        result.inventory.transactions_complete && result.inventory.statuses_complete &&
        result.inventory.outgoing_complete && result.caller_proof_id == first.proof.proof_id);
  const auto& tx = result.inventory.transactions.at(0);
  check(tx.account == std::string("0:") + number(1).to_hex() && tx.lt == 9 &&
        tx.now == 100 && tx.hash_hex == first.transaction_hash &&
        tx.orig == AccountStatus::uninit && tx.end == AccountStatus::active &&
        tx.pre_state_hash_hex == number(4).to_hex() &&
        tx.post_state_hash_hex == number(5).to_hex() &&
        tx.first_qualifying_message_hash_hex == a->get_hash().to_hex());
  const auto ext = fixture({b, c});
  check(inv::build(ext.source, ext.proof).inventory.transactions.at(0).first_qualifying_message_hash_hex ==
        c->get_hash().to_hex());
  const auto none = fixture({b, foreign});
  check(!inv::build(none.source, none.proof).inventory.transactions.at(0).first_qualifying_message_hash_hex);
  rejects<std::length_error>([&] { (void)inv::build(first.source, first.proof, {0, 10, 10, 1000}); });
  rejects<std::length_error>([&] { (void)inv::build(first.source, first.proof, {10, 0, 10, 1000}); });
  rejects<std::length_error>([&] { (void)inv::build(first.source, first.proof, {10, 10, 3, 1000}); });
  rejects<std::length_error>([&] { (void)inv::build(first.source, first.proof, {10, 10, 10, 0}); });
  const auto bad_lt = fixture({a}, 100, 10);
  rejects<std::invalid_argument>([&] { (void)inv::build(bad_lt.source, bad_lt.proof); });
  const auto bad_addr = fixture({a}, 100, 9, true);
  rejects<std::invalid_argument>([&] { (void)inv::build(bad_addr.source, bad_addr.proof); });
  const auto bad_time = fixture({a}, 101);
  rejects<std::invalid_argument>([&] { (void)inv::build(bad_time.source, bad_time.proof); });
  const auto bad_fees = fixture({a}, 100, 9, false, true);
  rejects<std::invalid_argument>([&] { (void)inv::build(bad_fees.source, bad_fees.proof); });
  const auto bad_outgoing_type = fixture({incoming_external()});
  rejects<std::invalid_argument>([&] { (void)inv::build(bad_outgoing_type.source, bad_outgoing_type.proof); });
  auto bad_root = first.proof;
  bad_root.expected_id.root_hash = number(7);
  rejects<std::invalid_argument>([&] { (void)inv::build(first.source, bad_root); });
  auto unproved = first.proof;
  unproved.first_included_verified = false;
  rejects<std::invalid_argument>([&] { (void)inv::build(first.source, unproved); });

  // Internal bounce=true is *not* bounced=true; only the latter is excluded.
  check(inv::detail::qualifies_outgoing(0, true, false));
  check(!inv::detail::qualifies_outgoing(0, true, true));
  check(inv::detail::qualifies_outgoing(1, true, false));
  check(!inv::detail::qualifies_outgoing(0, false, false));
  check(!inv::detail::qualifies_outgoing(1, false, false));
  rejected = false;
  try {
    (void)inv::detail::qualifies_outgoing(2, true, false); // external-in is not emitted
  } catch (const std::invalid_argument&) {
    rejected = true;
  }
  check(rejected);
  rejected = false;
  try {
    (void)inv::detail::qualifies_outgoing(1, true, true);
  } catch (const std::invalid_argument&) {
    rejected = true;
  }
  check(rejected);

  schema::BlockDataState missing;
  rejected = false;
  try {
    (void)inv::build(missing, {});
  } catch (const std::invalid_argument&) {
    rejected = true;
  }
  check(rejected);
  inv::CallerProof spoofed;
  spoofed.full_file_root_state_verified = true;
  spoofed.first_included_verified = true;
  spoofed.proof_id = "test-only-no-real-block";
  rejected = false;
  try {
    (void)inv::build(missing, spoofed);
  } catch (const std::invalid_argument&) {
    rejected = true;
  }
  check(rejected);
}
