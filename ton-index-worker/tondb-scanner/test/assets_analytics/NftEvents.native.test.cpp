// Native regression: generated TL-B transactions -> the ACTUAL DataParser
// transaction/message helpers -> NftEvents.cpp. No parser facsimile, NodeDB,
// network, or NFT classification. See NftEvents.native.cmake for the build hook.
#include "DataParser.h"
#include "assets_analytics/NftEvents.h"
#include "common/checksum.h"
#include "td/utils/crypto.h"
#include "validator/interfaces/block.h"
#include "vm/boc.h"

#include <cstdlib>
#include <iostream>

namespace {
using namespace assets_analytics::nft_events;
using Cell = td::Ref<vm::Cell>;
constexpr uint32_t seqno = 10, now = 1789516800;
constexpr uint64_t lt = 100;
const Budget budget{1, 16, 16, 1024 * 1024};

void require(bool condition, const char* message) {
  if (!condition) {
    std::cerr << message << '\n';
    std::abort();
  }
}

template <class T>
T must(td::Result<T> value) {
  if (value.is_error()) {
    std::cerr << value.error().message().str() << '\n';
    std::abort();
  }
  return value.move_as_ok();
}

// Test-only access to the existing private helper without changing DataParser,
// macro-rewriting its class, or copying its implementation. Explicit template
// instantiation may name a private member (C++ [temp.explicit]). Infer the private
// AccountStateShort map type from the member pointer instead of naming it.
struct TransactionsTag { friend auto transactions_method(TransactionsTag); };
template <auto Member>
struct TransactionsAccess {
  friend auto transactions_method(TransactionsTag) { return Member; }
};
template struct TransactionsAccess<&ParseQuery::parse_transactions>;

template <class Map>
std::vector<schema::Transaction> parse_transactions(
    td::Result<std::vector<schema::Transaction>> (ParseQuery::*method)(
        const ton::BlockIdExt&, const block::gen::Block::Record&,
        const block::gen::BlockInfo::Record&, const block::gen::BlockExtra::Record&, Map&),
    const ton::BlockIdExt& id, const block::gen::Block::Record& raw,
    const block::gen::BlockInfo::Record& info, const block::gen::BlockExtra::Record& extra) {
  // External inputs do not require execution config. Calling this exact helper
  // avoids inventing a masterchain ConfigInfo/account DB for ParseManager.
  ParseQuery query(seqno, {}, {}, {});
  Map states;
  auto result = must((query.*method)(id, raw, info, extra, states));
  require(result.size() == 1 && states.size() == 1, "production parser must visit the raw transaction");
  return result;
}

enum class Init { absent, inline_cell, ref };

Cell state_init(unsigned marker = 1) {
  auto code = vm::CellBuilder().store_long(marker, 32).finalize();
  auto data = vm::CellBuilder().store_long(marker + 1, 32).finalize();
  return vm::CellBuilder().store_long(6, 5) // 00 (split/special), 11 (code/data), 0 (library)
      .store_ref(code).store_ref(data).finalize();
}

Cell message(Init mode, Cell init, bool body_ref) {
  auto address = td::sha256_bits256("ordinary-non-NFT-account");
  vm::CellBuilder cb;
  cb.store_long(2, 2).store_zeroes(2) // ext_in_msg_info$10, addr_none$00
      .store_long(4, 3).store_long(-1, 8).store_bits(address.bits(), 256) // addr_std, no anycast
      .store_zeroes(4); // zero import_fee
  if (mode == Init::absent) {
    cb.store_zeroes(1);
  } else {
    cb.store_long(mode == Init::ref ? 3 : 2, 2); // just$1, right$1/left$0
    if (mode == Init::ref) cb.store_ref(init);
    else cb.append_cellslice(vm::load_cell_slice(init));
  }
  auto body = vm::CellBuilder().store_zeroes(32).finalize(); // ordinary comment, not NFT opcode
  cb.store_long(body_ref, 1);
  if (body_ref) cb.store_ref(body);
  else cb.append_cellslice(vm::load_cell_slice(body));
  return cb.finalize();
}

Cell description(bool has_message, bool accepted_init, bool committed) {
  vm::CellBuilder cb;
  if (has_message) cb.store_zeroes(7); // trans_ord$0000, credit_first, no storage/credit
  else cb.store_long(2, 4).store_zeroes(6); // trans_tick_tock$0010, zero storage fees/due/status
  if (committed) {
    auto details = vm::CellBuilder().store_zeroes(3 + 3 + 1 + 8 + 32 + 1 + 32 + 256 + 256).finalize();
    cb.store_long(1, 1).store_long(1, 1).store_long(accepted_init, 1).store_long(accepted_init, 1)
        .store_zeroes(4).store_ref(details); // successful VM, zero gas_fees
  } else {
    cb.store_zeroes(3); // compute_skipped, cskip_no_state
  }
  cb.store_zeroes(1).store_long(!committed, 1); // no action, aborted
  if (has_message) cb.store_zeroes(1); // no bounce
  return cb.store_zeroes(1).finalize(); // not destroyed
}

struct RawTransaction { Cell root, update; };
RawTransaction transaction(Cell msg, bool accepted_init, bool committed, bool changed) {
  auto address = td::sha256_bits256("ordinary-non-NFT-account");
  auto before = td::sha256_bits256("before"), after = td::sha256_bits256("after");
  if (!changed) after = before;
  auto update = vm::CellBuilder().store_long(0x72, 8).store_bits(before.bits(), 256)
      .store_bits(after.bits(), 256).finalize();
  vm::CellBuilder messages;
  messages.store_long(msg.not_null(), 1);
  if (msg.not_null()) messages.store_ref(msg);
  messages.store_zeroes(1); // no outgoing messages
  auto root = vm::CellBuilder().store_long(7, 4).store_bits(address.bits(), 256)
      .store_long(lt, 64).store_zeroes(256 + 64).store_long(now, 32).store_zeroes(15)
      .store_long(accepted_init ? schema::uninit : schema::active, 2).store_long(schema::active, 2)
      .store_ref(messages.finalize()).store_zeroes(5) // CurrencyCollection = zero grams, no extras
      .store_ref(update).store_ref(description(msg.not_null(), accepted_init, committed)).finalize();
  return {root, update};
}

struct BlockData final : ton::validator::BlockData {
  ton::BlockIdExt id;
  Cell root;
  std::string bytes;
  BlockData(ton::BlockIdExt id, Cell root, std::string bytes)
      : id(id), root(std::move(root)), bytes(std::move(bytes)) {}
  td::BufferSlice data() const override { return td::BufferSlice(bytes); }
  ton::FileHash file_hash() const override { return id.file_hash; }
  ton::BlockIdExt block_id() const override { return id; }
  Cell root_cell() const override { return root; }
};

struct Fixture {
  ParsedBlock parsed;
  BlockId anchor;
  schema::Transaction& tx() { return parsed.blocks_.front().transactions.front(); }
  Result extract() const { return assets_analytics::nft_events::extract(parsed, anchor, budget); }
};

Fixture fixture(Cell msg, bool accepted_init = false, bool committed = false, bool changed = true) {
  auto tx = transaction(msg, accepted_init, committed, changed);
  auto address = td::sha256_bits256("ordinary-non-NFT-account");
  vm::AugmentedDictionary transactions{64, block::tlb::aug_AccountTransactions};
  require(transactions.set_ref(td::BitArray<64>{static_cast<long long>(lt)}, tx.root), "insert raw transaction");
  vm::CellBuilder account;
  account.store_long(5, 4).store_bits(address.bits(), 256)
      .append_cellslice(vm::load_cell_slice(std::move(transactions).extract_root_cell())).store_ref(tx.update);
  vm::AugmentedDictionary accounts{256, block::tlb::aug_ShardAccountBlocks};
  require(accounts.set_builder(address, account), "insert raw AccountBlock");

  // Generated block envelope containing the SAME dictionary the parser consumes.
  // No claim that its synthetic state/config is an executable archive snapshot.
  auto empty = vm::CellBuilder().finalize();
  block::gen::BlockExtra::Record extra{};
  extra.in_msg_descr = empty; extra.out_msg_descr = empty;
  extra.account_blocks = accounts.get_wrapped_dict_root();
  extra.rand_seed = address; extra.created_by = address;
  extra.custom = vm::load_cell_slice_ref(vm::CellBuilder().store_zeroes(1).finalize());
  Cell extra_cell;
  require(tlb::pack_cell(extra_cell, extra), "pack BlockExtra");
  auto prev = vm::CellBuilder().store_long(lt - 1, 64).store_long(seqno - 1, 32)
      .store_bits(address.bits(), 256).store_bits(address.bits(), 256).finalize();
  auto info_cell = vm::CellBuilder().store_long(0x9bc7a987, 32).store_zeroes(32 + 8 + 8)
      .store_long(seqno, 32).store_zeroes(32 + 8).store_long(-1, 32).store_zeroes(64)
      .store_long(now, 32).store_long(lt, 64).store_long(lt + 1, 64).store_zeroes(128)
      .store_ref(prev).finalize();
  auto four_balances = vm::CellBuilder().store_zeroes(20).finalize();
  auto flow = vm::CellBuilder().store_long(0xb8e48dfb, 32).store_ref(four_balances)
      .store_zeroes(5).store_ref(four_balances).finalize();
  auto state_before = vm::CellBuilder().store_long(1, 8).finalize();
  auto state_after = vm::CellBuilder().store_long(2, 8).finalize();
  auto root = vm::CellBuilder().store_long(0x11ef55aa, 32).store_long(-239, 32)
      .store_ref(info_cell).store_ref(flow)
      .store_ref(vm::CellBuilder::create_merkle_update(state_before, state_after)).store_ref(extra_cell).finalize();
  auto boc = must(vm::std_boc_serialize(root));
  ton::BlockIdExt id{-1, ton::shardIdAll, seqno, root->get_hash().as_bits256(), td::sha256_bits256(boc.as_slice())};
  block::gen::Block::Record raw;
  block::gen::BlockInfo::Record info;
  require(tlb::unpack_cell(root, raw) && tlb::unpack_cell(raw.info, info) && tlb::unpack_cell(raw.extra, extra),
          "unpack generated block envelope");
  schema::Block b{};
  b.workchain = -1; b.shard = static_cast<int64_t>(ton::shardIdAll); b.seqno = seqno;
  b.gen_utime = now; b.start_lt = lt; b.end_lt = lt + 1;
  b.root_hash = td::base64_encode(id.root_hash.as_slice()); b.file_hash = td::base64_encode(id.file_hash.as_slice());
  b.mc_block_workchain = b.workchain; b.mc_block_shard = b.shard; b.mc_block_seqno = seqno;
  b.transactions = parse_transactions(transactions_method(TransactionsTag{}), id, raw, info, extra);
  require(b.transactions.front().raw->get_hash() == tx.root->get_hash(), "parser retains original transaction root");
  schema::BlockDataState source;
  source.block_data = td::Ref<BlockData>{true, id, root, boc.as_slice().str()};
  Fixture f;
  f.anchor = {b.workchain, b.shard, b.seqno, b.root_hash, b.file_hash};
  f.parsed.blocks_.push_back(std::move(b));
  f.parsed.mc_block_.shard_blocks_diff_.push_back(std::move(source));
  return f;
}

void reject(Fixture f, const char* why) {
  auto result = f.extract();
  require(!result.ok() && result.candidates.empty(), why);
}

std::string boc64(Cell cell) {
  return td::base64_encode(must(vm::std_boc_serialize(cell, vm::BagOfCells::WithCRC32C)).as_slice());
}

// Valid CRC32C BoC with one root PLUS an unreachable cell tree. TON's general
// decoder accepts this and returns the original root, so hash-only checks cannot
// detect it. DataParser never emits it: it serializes exactly the root DAG.
std::string with_unreachable_cells(Cell root, Cell other) {
  vm::BagOfCells multi;
  multi.set_roots({root, other});
  auto status = multi.import_cells();
  require(status.is_ok(), "import multi-root BoC");
  auto bytes = must(multi.serialize_to_slice(vm::BagOfCells::WithCRC32C)).as_slice().str();
  vm::BagOfCells::Info info;
  require(info.parse_serialized_header(bytes) == static_cast<long long>(bytes.size()) &&
              info.ref_byte_size == 1 && info.root_count == 2, "small multi-root BoC header");
  bytes[7] = 1; // root_count, after magic/flags/offset_bytes/cell_count
  bytes.erase(info.roots_offset + 1, 1); // remove only the second root index, retain its cells
  bytes.resize(bytes.size() - 4);
  auto crc = td::crc32c(bytes);
  for (unsigned shift = 0; shift != 32; shift += 8) bytes.push_back(static_cast<char>(crc >> shift));
  require(must(vm::std_boc_deserialize(bytes))->get_hash() == root->get_hash(),
          "unreachable-cell negative must keep a valid BoC and original root");
  return td::base64_encode(bytes);
}
} // namespace

int main() {
  auto init = state_init();
  auto absent = fixture({});
  require(!absent.tx().in_msg && absent.extract().ok() && absent.extract().candidates.empty(),
          "tick/tock without incoming message is valid and not an NFT candidate");
  auto unchanged = fixture(message(Init::absent, {}, false), false, true, false).extract();
  require(unchanged.ok() && unchanged.examined_transactions == 1 && unchanged.candidates.empty(),
          "successful ordinary no-init transaction with unchanged state is not an NFT candidate");
  for (bool body_ref : {false, true}) {
    for (auto mode : {Init::absent, Init::inline_cell, Init::ref}) {
      auto f = fixture(message(mode, init, body_ref));
      auto result = f.extract();
      require(result.ok() && result.examined_transactions == 1 && result.candidates.empty(),
              "production-parsed non-NFT transaction must pass even with no candidate");
      block::gen::Transaction::Record raw;
      require(tlb::unpack_cell(f.tx().raw, raw) && raw.r1.in_msg->prefetch_long(1) == -1 &&
                  raw.r1.in_msg->prefetch_ulong(1) == 1,
              "pinned TL-B Maybe just$1 is signed -1, unsigned 1");
      if (mode == Init::absent) {
        require(f.tx().in_msg->init_state.is_null() && !f.tx().in_msg->init_state_boc,
                "no-init parser null semantics");
      } else {
        require(f.tx().in_msg->init_state->get_hash() == init->get_hash() &&
                    f.tx().in_msg->init_state_boc == boc64(init),
                "parser strips Maybe/Either tags and stores base64 CRC32C BoC");
      }
    }
  }

  for (auto mode : {Init::inline_cell, Init::ref}) {
    auto f = fixture(message(mode, init, false), true, true);
    auto result = f.extract();
    require(result.ok() && result.candidates.size() == 1, "successful activation gives only an init lead");
    auto& c = result.candidates.front();
    require(c.supplied_state_init_hash == init->get_hash().to_hex() &&
                c.accepted_state_init_hash == c.supplied_state_init_hash && c.accepted_state_init_boc &&
                td::base64_encode(*c.accepted_state_init_boc) == *f.tx().in_msg->init_state_boc &&
                must(vm::std_boc_deserialize(*c.accepted_state_init_boc))->get_hash() == init->get_hash(),
            "candidate evidence contains the bound BINARY BoC, not base64 text");
    require(!Result::minted_verified && !Result::lifetime_complete, "init lead is not an NFT count");
  }
  auto supplied = fixture(message(Init::ref, init, false), false, true).extract();
  require(supplied.ok() && supplied.candidates.size() == 1 && supplied.candidates[0].supplied_state_init_hash &&
              !supplied.candidates[0].accepted_state_init_hash && !supplied.candidates[0].accepted_state_init_boc,
          "supplied init without activation flags must not be called accepted");

  const auto valid = fixture(message(Init::ref, init, false), true, true);
  auto bad = valid; bad.tx().in_msg.reset(); reject(std::move(bad), "missing parsed incoming message");
  bad = absent; bad.tx().in_msg = valid.parsed.blocks_[0].transactions[0].in_msg;
  reject(std::move(bad), "fabricated incoming message on tick/tock");
  bad = valid; bad.tx().in_msg->hash = td::sha256_bits256("wrong-message");
  reject(std::move(bad), "wrong parsed message hash");
  bad = valid;
  require(bad.tx().in_msg->hash_norm && *bad.tx().in_msg->hash_norm != bad.tx().in_msg->hash,
          "fixture external has a distinct normalized hash");
  bad.tx().in_msg->hash = *bad.tx().in_msg->hash_norm;
  reject(std::move(bad), "normalized external hash cannot replace raw message hash");
  bad = valid; bad.tx().hash = td::sha256_bits256("wrong-transaction");
  reject(std::move(bad), "raw transaction hash binding");
  bad = valid; bad.parsed.blocks_[0].root_hash = td::base64_encode(td::sha256_bits256("wrong-block").as_slice());
  reject(std::move(bad), "raw source block root binding");
  bad = valid; bad.parsed.blocks_[0].file_hash = td::base64_encode(td::sha256_bits256("wrong-block-file").as_slice());
  reject(std::move(bad), "raw source block file binding");
  bad = valid; bad.tx().in_msg->init_state.clear(); bad.tx().in_msg->init_state_boc.reset();
  reject(std::move(bad), "raw StateInit cannot disappear from parsed input");
  auto other = state_init(99);
  bad = valid; bad.tx().in_msg->init_state = other;
  reject(std::move(bad), "different parsed StateInit");
  bad = valid; bad.tx().in_msg->init_state = other; bad.tx().in_msg->init_state_boc = boc64(other);
  reject(std::move(bad), "self-consistent substitute StateInit must still bind to raw message");
  bad = fixture(message(Init::absent, {}, false));
  bad.tx().in_msg->init_state = init; bad.tx().in_msg->init_state_boc = boc64(init);
  reject(std::move(bad), "fabricated StateInit on no-init message");
  for (auto invalid : {std::string{}, std::string("not base64!"), boc64(other),
                       with_unreachable_cells(init, other)}) {
    bad = valid; bad.tx().in_msg->init_state_boc = std::move(invalid);
    reject(std::move(bad), "empty/invalid/different/unreachable-cell BoC");
  }
  auto bytes = must(td::base64_decode(*valid.parsed.blocks_[0].transactions[0].in_msg->init_state_boc));
  auto tampered = bytes; tampered.back() ^= 1;
  for (auto invalid : {td::base64_encode(tampered), td::base64_encode(bytes + "trailing"),
                       td::base64_encode(bytes + bytes), bytes}) {
    bad = valid; bad.tx().in_msg->init_state_boc = std::move(invalid);
    reject(std::move(bad), "tampered CRC/trailing bytes/concatenated BoCs/binary in base64 field");
  }
  auto multi = must(vm::std_boc_serialize_multi({init, other}, vm::BagOfCells::WithCRC32C));
  bad = valid; bad.tx().in_msg->init_state_boc = td::base64_encode(multi.as_slice());
  reject(std::move(bad), "extra BoC root");
  std::cout << "NftEvents native DataParser correspondence tests PASS\n";
}
