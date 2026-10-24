#include "WalletRawInventory.h"

#include "crypto/block/block-auto.h"
#include "crypto/block/block-parse.h"
#include "crypto/vm/boc.h"
#include "crypto/vm/cells/DataCell.h"
#include "crypto/vm/dict.h"
#include "common/checksum.h"
#include "td/utils/crypto.h"

#include <cstdint>
#include <set>
#include <stdexcept>
#include <tuple>
#include <utility>
#include <vector>

namespace ton_analytics::wallets::raw_inventory {
namespace {

void require(bool ok, const char* reason) {
  if (!ok) throw std::invalid_argument(reason);
}

void under_cap(std::size_t seen, std::size_t maximum, const char* reason) {
  if (seen >= maximum) throw std::length_error(reason);
}

// BlockQ owns a StaticBagOfCellsDbLazy over the ORIGINAL BoC. Its root also
// retains that decoder; child ExtCells have weak decoder refs. Do not confuse
// these with CellDB-backed shard-state cells. BufferSlice::clone shares bytes.
// A native lazy load may also decode unhashed children, so bound the whole BoC
// BEFORE any load, in addition to charging each inventory traversal edge below.
// Empty bytes are supported only for legacy, fully eager in-memory callers.
bool bounded_backing(const ton::validator::BlockData& source, const ton::BlockIdExt& id,
                     std::size_t max_cells) {
  auto bytes = source.data();
  if (bytes.empty()) return false;
  vm::BagOfCells::Info header;
  require(header.parse_serialized_header(bytes.as_slice()) > 0 && header.valid &&
              header.total_size == bytes.size() && header.root_count == 1 && header.absent_count == 0,
          "damaged/incomplete original raw block BoC header");
  if (static_cast<std::size_t>(header.cell_count) > max_cells)
    throw std::length_error("raw block backing BoC cell cap exceeded");
  require(td::sha256_bits256(bytes.as_slice()) == id.file_hash,
          "original raw block BoC file hash disagrees with full block ID");
  return true;
}

// One preparation per block; no transaction-sized/full-block copies. Keep all
// prepared data alive through dictionary validation. Every scheduled edge is
// charged (including repeats), before loading it or growing the work stack.
class Preparation {
 public:
  Preparation(std::size_t maximum, bool bounded) : maximum_(maximum), bounded_(bounded) {}

  td::Ref<vm::DataCell> one(const td::Ref<vm::Cell>& cell) {
    under_cap(count_, maximum_, "raw block reachable-cell cap exceeded");
    ++count_;
    require(cell.not_null(), "missing raw inventory cell reference");
    require(!cell->is_virtualized(), "virtualized raw inventory cell");
    require(cell->is_loaded() || bounded_, "original BoC unavailable for bounded lazy raw inventory load");
    auto loaded = cell->load_cell();
    if (loaded.is_error())
      throw std::invalid_argument("raw inventory cell load failed [" + cell->get_hash().to_hex() +
                                  "]: " + loaded.error().message().str());
    auto data = loaded.move_as_ok().data_cell;
    require(data.not_null(), "raw inventory cell loader returned null data");
    const auto identity = cell->check_equals_unloaded(data);
    require(identity.is_ok(), "damaged raw inventory cell: loaded hash/depth/level mismatch");
    require(data->special_type() != vm::Cell::SpecialType::PrunnedBranch,
            "pruned raw inventory cell (incomplete transaction/message evidence)");
    retained_.push_back(data);
    return data;
  }

  void graph(const td::Ref<vm::Cell>& root) {
    std::vector<td::Ref<vm::Cell>> pending{root};
    while (!pending.empty()) {
      auto cell = std::move(pending.back());
      pending.pop_back();
      auto data = one(cell);
      // count_ <= maximum_; pending is already reserved against the remainder.
      if (data->get_refs_cnt() > maximum_ - count_ - pending.size())
        throw std::length_error("raw block reachable-cell cap exceeded before reference expansion");
      for (unsigned n = 0; n < data->get_refs_cnt(); ++n) {
        auto ref = data->get_ref(n);
        require(ref.not_null(), "missing raw inventory cell reference");
        pending.push_back(std::move(ref));
      }
    }
  }

  std::size_t count() const { return count_; }

 private:
  std::size_t maximum_;
  bool bounded_;
  std::size_t count_ = 0;
  std::vector<td::Ref<vm::DataCell>> retained_;
};

bool source_matches(td::Ref<vm::CellSlice> slice, const block::StdAddress& account) {
  if (slice.is_null() || block::gen::t_MsgAddressInt.get_tag(*slice) != block::gen::MsgAddressInt::addr_std)
    return false; // addr_var is not the canonical raw wc:256-bit account address
  block::StdAddress source;
  return block::tlb::t_MsgAddressInt.extract_std_address(slice, source, true) && source == account;
}

// Validate the entire actual Message Any cell; never derive activity from an
// action-phase request, counter alone, bounce flag, or parsed event list.
bool emitted_message(const td::Ref<vm::Cell>& cell, const block::StdAddress& account) {
  require(cell.not_null(), "missing emitted out-message cell");
  block::gen::Message::Record message;
  require(tlb::type_unpack_cell(cell, block::gen::t_Message_Any, message) && message.info.not_null(),
          "malformed emitted out-message");
  const auto kind = block::gen::CommonMsgInfo().get_tag(*message.info);
  if (kind == block::gen::CommonMsgInfo::int_msg_info) {
    block::gen::CommonMsgInfo::Record_int_msg_info info;
    require(tlb::csr_unpack(message.info, info), "malformed internal out-message info");
    return detail::qualifies_outgoing(0, source_matches(info.src, account), info.bounced);
  }
  if (kind == block::gen::CommonMsgInfo::ext_out_msg_info) {
    block::gen::CommonMsgInfo::Record_ext_out_msg_info info;
    require(tlb::csr_unpack(message.info, info), "malformed external-out message info");
    return detail::qualifies_outgoing(1, source_matches(info.src, account), false);
  }
  throw std::invalid_argument("external-in/unknown message in raw out_msgs");
}

} // namespace

namespace detail {

AccountStatus status(int native_tag) {
  switch (native_tag) {
    case block::gen::AccountStatus::acc_state_nonexist: return AccountStatus::nonexist;
    case block::gen::AccountStatus::acc_state_uninit: return AccountStatus::uninit;
    case block::gen::AccountStatus::acc_state_active: return AccountStatus::active;
    case block::gen::AccountStatus::acc_state_frozen: return AccountStatus::frozen;
    default: throw std::invalid_argument("invalid native transaction account status");
  }
}

bool qualifies_outgoing(int kind, bool source_matches_account, bool bounced) {
  if (kind != 0 && kind != 1) throw std::invalid_argument("inconsistent out-message type");
  if (kind == 1 && bounced) throw std::invalid_argument("external-out cannot have bounced flag");
  return source_matches_account && (kind == 1 || !bounced);
}

} // namespace detail

Result build(const schema::BlockDataState& source, const CallerProof& proof, Limits limits) {
  require(proof.full_file_root_state_verified && proof.first_included_verified &&
              !proof.proof_id.empty(), "missing caller's full-file/root/state/first-inclusion proof");
  require(source.handle && source.block_data.not_null() && source.block_state.not_null(),
          "missing verified block data, state or handle");
  const auto& id = proof.expected_id;
  require(source.handle->id() == id && source.block_data->block_id() == id && id.id.seqno != 0 &&
              id.root_hash != ton::RootHash::zero() && id.file_hash != ton::FileHash::zero(),
          "raw source full block ID disagrees with caller/handle/data");
  const auto root = source.block_data->root_cell();
  require(root.not_null() && root->get_hash().as_bits256() == id.root_hash,
          "raw source representation root hash disagrees with full block ID");

  Result out;
  out.caller_proof_id = proof.proof_id;
  const char* decode_scope = "bounded raw preparation";
  try {
    Preparation prepared(limits.max_cells, bounded_backing(*source.block_data, id, limits.max_cells));
    decode_scope = "Block/BlockInfo/BlockExtra";
    block::gen::Block::Record block;
    block::gen::BlockInfo::Record info;
    block::gen::BlockExtra::Record extra;
    require(tlb::unpack_cell(prepared.one(root), block) && block.info.not_null() && block.extra.not_null() &&
                tlb::unpack_cell(prepared.one(block.info), info) &&
                tlb::unpack_cell(prepared.one(block.extra), extra),
            "malformed raw Block/BlockInfo/BlockExtra");
    require(info.shard.not_null() && info.seq_no == id.id.seqno &&
                info.not_master == (id.id.workchain != -1), "raw BlockInfo identity mismatch");
    block::ShardId shard(info.shard);
    require(shard.is_valid() && shard.workchain_id == id.id.workchain && shard.shard_pfx == id.id.shard,
            "raw BlockInfo shard differs from caller's full ID");
    out.inventory.id = {id.id.workchain, id.id.shard, id.id.seqno,
                        id.root_hash.to_hex(), id.file_hash.to_hex()};
    out.inventory.gen_utime = info.gen_utime;
    require(extra.account_blocks.not_null(), "missing raw AccountBlocks dictionary");

    // Only this closure is consumed below. In particular NEVER follow the
    // block's Merkle state_update into old/new shard states. Its proof belongs
    // to the caller; pruned witnesses there are normal, not missing tx evidence.
    decode_scope = "AccountBlocks preparation";
    prepared.graph(extra.account_blocks);
    out.reachable_cell_references = prepared.count();

    // Traversal/augmentation validation is independent of DataParser. For each
    // account validate every LT-keyed transaction, even if it is not a wallet.
    decode_scope = "AccountBlocks";
    // This *augmented* constructor checks the outer HashmapAugE root fee
    // augmentation against the tree (including the valid empty-dict case).
    vm::AugmentedDictionary accounts{vm::load_cell_slice_ref(extra.account_blocks), 256,
                                      block::tlb::aug_ShardAccountBlocks};
    std::set<std::pair<std::string, std::uint64_t>> seen;
    const bool valid = accounts.validate_check_extra(
        [&](td::Ref<vm::CellSlice> value, td::Ref<vm::CellSlice>, td::ConstBitPtr key, int bits) {
          under_cap(out.account_count, limits.max_accounts, "raw account cap exceeded");
          ++out.account_count;
          if (bits != 256 || value.is_null()) return false;
          block::gen::AccountBlock::Record account;
          if (!tlb::csr_unpack(value, account) || !key.equals(account.account_addr.bits(), 256))
            return false;
          const auto account_name = std::to_string(id.id.workchain) + ":" + account.account_addr.to_hex();
          const block::StdAddress address(id.id.workchain, account.account_addr);
          decode_scope = "AccountBlock.transactions";
          vm::AugmentedDictionary transactions{vm::DictNonEmpty(), account.transactions, 64,
                                               block::tlb::aug_AccountTransactions};
          return transactions.validate_check_extra(
              [&](td::Ref<vm::CellSlice> entry, td::Ref<vm::CellSlice>, td::ConstBitPtr lt_key, int lt_bits) {
                under_cap(out.inventory.transactions.size(), limits.max_transactions,
                          "raw transaction cap exceeded");
                if (lt_bits != 64 || entry.is_null() || entry->size() != 0 || entry->size_refs() != 1)
                  return false;
                const auto tx_cell = entry->prefetch_ref();
                block::gen::Transaction::Record tx;
                if (tx_cell.is_null() || !tlb::unpack_cell(tx_cell, tx) ||
                    tx.account_addr != account.account_addr || tx.lt == 0 ||
                    td::bitstring::bits_load_ulong(lt_key, 64) != tx.lt || tx.now != info.gen_utime ||
                    tx.outmsg_cnt < 0 || tx.outmsg_cnt > 32767 ||
                    !seen.emplace(account_name, tx.lt).second) return false;
                stage::RawTransaction row;
                row.account = account_name;
                row.lt = tx.lt;
                row.hash_hex = tx_cell->get_hash().to_hex();
                row.now = tx.now;
                row.orig = detail::status(tx.orig_status);
                row.end = detail::status(tx.end_status);
                block::gen::HASH_UPDATE::Record hashes;
                if (!tlb::type_unpack_cell(tx.state_update, block::gen::t_HASH_UPDATE_Account, hashes))
                  return false;
                row.pre_state_hash_hex = hashes.old_hash.to_hex();
                row.post_state_hash_hex = hashes.new_hash.to_hex();
                if (static_cast<std::size_t>(tx.outmsg_cnt) > limits.max_out_messages - out.out_message_count)
                  throw std::length_error("raw out-message cap exceeded");
                decode_scope = "Transaction.out_msgs";
                vm::Dictionary messages{tx.r1.out_msgs, 15};
                unsigned index = 0;
                if (!messages.check_for_each([&](td::Ref<vm::CellSlice> msg, td::ConstBitPtr msg_key, int msg_bits) {
                      if (msg_bits != 15 || msg.is_null() || msg->size() != 0 ||
                          msg->size_refs() != 1 || index >= static_cast<unsigned>(tx.outmsg_cnt) ||
                          td::bitstring::bits_load_ulong(msg_key, 15) != index) return false;
                      auto cell = msg->prefetch_ref();
                      const bool qualifies = emitted_message(cell, address);
                      if (qualifies && !row.first_qualifying_message_hash_hex)
                        row.first_qualifying_message_hash_hex = cell->get_hash().to_hex();
                      ++index;
                      return true;
                    }) || index != static_cast<unsigned>(tx.outmsg_cnt)) return false;
                out.out_message_count += index;
                out.inventory.transactions.push_back(std::move(row));
                return true;
              });
        });
    if (!valid) throw std::invalid_argument(std::string("missing/malformed AccountBlocks, LT dictionary or out_msgs at ") +
                                             decode_scope);
    out.inventory.transactions_complete = true;
    out.inventory.statuses_complete = true;
    out.inventory.outgoing_complete = true;
    return out;
  } catch (const vm::VmError& e) {
    throw std::invalid_argument(std::string("invalid raw TL-B at ") + decode_scope + ": " + e.get_msg());
  }
}

} // namespace ton_analytics::wallets::raw_inventory
