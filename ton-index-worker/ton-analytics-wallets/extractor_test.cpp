#include "WalletEventExtractor.h"
#include "WalletMetrics.h" // The extractor's event types must not collide with reducer types.

#include "vm/db/DynamicBagOfCellsDb.h"

#include <cassert>
#include <map>
#include <stdexcept>
#include <string>
#include <type_traits>

using namespace ton_analytics::wallets::events;
static_assert(!std::is_same_v<ton_analytics::wallets::BlockId, BlockId>);
static_assert(!std::is_same_v<ton_analytics::wallets::CodeEvidence, CodeEvidence>);

namespace {
td::Bits256 bits(const char* hex) {
  td::Bits256 result;
  assert(result.from_hex(td::Slice(hex)));
  return result;
}
constexpr char kV5[] = "20834b7b72b112147e1b2fb457b84e74d1a30f04f737d4f62a668e9552d2b72f";
constexpr char kExcluded[] = "45ebbce9b5d235886cb6bfe1c3ad93b708de058244892365c9ee0dfe439cb7b5";
constexpr char kOther[] = "0000000000000000000000000000000000000000000000000000000000000001";
constexpr char kAddress[] = "1111111111111111111111111111111111111111111111111111111111111111";
constexpr char kTxHash[] = "2222222222222222222222222222222222222222222222222222222222222222";

struct Resolver final : VerifiedCodeResolver {
  const char* pre = nullptr;
  const char* post = nullptr;
  bool verified = true;
  bool wrong_hash = false;
  CodeEvidence resolve(const schema::Transaction& tx, CodeUse use) override {
    auto hash = use == CodeUse::execution ? pre : post;
    if (!hash) return {};
    return {Resolution::resolved, bits(hash),
            wrong_hash ? bits(kTxHash) : (use == CodeUse::execution ? tx.account_state_hash_before
                                                                   : tx.account_state_hash_after),
            "fixture_verified_historical_state", verified};
  }
};

struct CellReader final : vm::CellDbReader {
  std::map<std::string, td::Ref<vm::DataCell>> cells;
  td::Result<td::Ref<vm::DataCell>> load_cell(td::Slice hash) override {
    auto it = cells.find(hash.str());
    if (it == cells.end()) return td::Status::Error("historical cell unavailable");
    return it->second;
  }
  td::Result<std::vector<td::Ref<vm::DataCell>>> load_bulk(td::Span<td::Slice>) override {
    return td::Status::Error("not needed by wallet extractor");
  }
  td::Ref<vm::Cell> create_unloaded_cell(const td::Ref<vm::Cell>&, int) override { return {}; }
};

// TL-B Account with a real address, AccountStorage and StateInit; the root hash
// is used as the transaction's HASH_UPDATE endpoint, not an address lookup.
td::Ref<vm::DataCell> account_cell(const char* address, td::Ref<vm::DataCell> code, bool active = true) {
  vm::CellBuilder b;
  assert(b.store_long_bool(1, 1)       // account$1
         && b.store_long_bool(4, 3)    // addr_std$10, no anycast
         && b.store_long_bool(0, 8)    // workchain 0
         && b.store_bits_bool(bits(address))
         && b.store_long_bool(0, 3)    // StorageUsed.cells VarUInteger 7
         && b.store_long_bool(0, 3)    // StorageUsed.bits
         && b.store_long_bool(0, 3)    // StorageExtraInfo: none
         && b.store_long_bool(0, 32)   // last_paid
         && b.store_long_bool(0, 1)    // due_payment: nothing
         && b.store_long_bool(101, 64) // AccountStorage.last_trans_lt
         && b.store_long_bool(0, 4)    // balance.grams: zero
         && b.store_long_bool(0, 1));  // balance.other: empty
  if (active) {
    assert(b.store_long_bool(1, 1)    // account_active$1
           && b.store_long_bool(0, 1) // StateInit.fixed_prefix_length: nothing
           && b.store_long_bool(0, 1) // special: nothing
           && b.store_long_bool(1, 1) // code: just ref
           && b.store_ref_bool(code)
           && b.store_long_bool(0, 1) // data: nothing
           && b.store_long_bool(0, 1)); // library: nothing
  } else {
    assert(b.store_long_bool(0, 2));  // account_uninit$00
  }
  return b.finalize();
}

schema::Message internal(const char* source, bool bounced = false, bool bounce = true) {
  schema::Message m{};
  m.hash = bits(kOther);
  m.source = source;
  m.destination = "0:2222222222222222222222222222222222222222222222222222222222222222";
  m.bounced = bounced;
  m.bounce = bounce;
  return m;
}

schema::Transaction transaction() {
  schema::Transaction tx{};
  tx.account = block::StdAddress(0, bits(kAddress));
  tx.hash = bits(kTxHash);
  tx.lt = 100;
  tx.now = 172800 + 5;
  tx.mc_seqno = 10;
  tx.orig_status = schema::active;
  tx.end_status = schema::nonexist; // self-destruct: post-code cannot justify the send
  tx.account_state_hash_before = bits(kOther);
  tx.account_state_hash_after = bits(kTxHash);
  tx.description = schema::TransactionDescr_ord{};
  return tx;
}

schema::Block mc() {
  schema::Block b{};
  b.workchain = -1;
  b.shard = static_cast<int64_t>(0x8000000000000000ULL);
  b.seqno = 10;
  b.root_hash = "mc-root";
  b.file_hash = "mc-file";
  return b;
}
schema::Block shard() {
  schema::Block b{};
  b.workchain = 0;
  b.shard = static_cast<int64_t>(0x8000000000000000ULL);
  b.seqno = 75;
  b.root_hash = "shard-root";
  b.file_hash = "shard-file";
  b.mc_block_workchain = -1;
  b.mc_block_shard = mc().shard;
  b.mc_block_seqno = 10;
  return b;
}

Batch run(const schema::Transaction& tx, Resolver& resolver,
          const std::vector<schema::AccountState>& states = {}) {
  auto m = mc();
  auto s = shard();
  s.transactions.push_back(tx);
  return extract_included({m, s}, {-1, m.shard, m.seqno, m.root_hash, m.file_hash}, resolver, states);
}

void regressions() {
  auto tx = transaction();
  const auto address = std::string("0:") + kAddress;
  tx.in_msg = internal(address.c_str()); // extension/internal entrypoint must not be filtered
  tx.in_msg->opcode = 0x6578746e;
  tx.out_msgs.push_back(internal(address.c_str(), true));
  tx.out_msgs.push_back(internal(address.c_str(), false, true)); // bounce=true is permitted
  auto external = schema::Message{};
  external.hash = bits(kTxHash);
  external.source = address;
  // External-out: destination/bounced are both absent.
  tx.out_msgs.push_back(external);
  Resolver r;
  r.pre = kV5;
  r.post = kExcluded;
  auto result = run(tx, r);
  assert(result.included_blocks.size() == 2);
  assert(result.sends.size() == 1); // 2 legitimate messages, one tx/account/day fact
  assert(result.sends[0].execution_code.classification == Classification::included_wallet);
  assert(result.sends[0].execution_code.wallet_type_id == "wallet_v5r1");
  assert(result.sends[0].tx.utc_day_start == 172800);
  assert(result.sends[0].tx.mc.root_hash == "mc-root");
  assert(result.sends[0].tx.shard.file_hash == "shard-file");
  assert(result.sends[0].tx.pre_state_hash_hex == tx.account_state_hash_before.to_hex());
  assert(result.sends[0].tx.post_state_hash_hex == tx.account_state_hash_after.to_hex());
  assert(result.sends[0].tx.pre_state_hash_hex != result.sends[0].tx.post_state_hash_hex);
  assert(result.active_witnesses.size() == 1); // orig_status active even after destruction
  assert(result.active_witnesses[0].tx.pre_state_hash_hex == result.sends[0].tx.pre_state_hash_hex);
  assert(result.active_witnesses[0].tx.post_state_hash_hex == result.sends[0].tx.post_state_hash_hex);
  assert(result.active_witnesses[0].post_state_hash_hex == result.sends[0].tx.post_state_hash_hex);
  assert(result.active_witnesses[0].post_code.classification == Classification::pending);

  r.pre = nullptr;
  auto missing = run(tx, r);
  assert(missing.sends[0].execution_code.classification == Classification::pending);
  assert(missing.pending_execution_codes == 1); // post-code excluded != execution code
  // A parser-supplied immutable Account cell is usable ONLY with the same account
  // and exact HASH_UPDATE pre-state hash, not merely its latest address/code.
  schema::AccountState pre{};
  pre.account = tx.account;
  pre.hash = tx.account_state_hash_before;
  pre.account_status = "active";
  pre.code = vm::CellBuilder().finalize();
  pre.code_hash = td::Bits256(pre.code->get_hash().bits());
  assert(run(tx, r, {pre}).sends[0].execution_code.source == "parsed_exact_account_state");
  pre.hash = tx.account_state_hash_after;
  assert(run(tx, r, {pre}).sends[0].execution_code.classification == Classification::pending);
  pre.hash = tx.account_state_hash_before;
  pre.account = block::StdAddress(0, bits(kTxHash));
  assert(run(tx, r, {pre}).sends[0].execution_code.classification == Classification::pending);
  r.pre = kV5;
  r.wrong_hash = true;
  assert(run(tx, r).sends[0].execution_code.classification == Classification::pending);
  r.wrong_hash = false;
  r.verified = false;
  assert(run(tx, r).sends[0].execution_code.classification == Classification::pending);
  r.verified = true;
  r.pre = kExcluded;
  assert(run(tx, r).sends[0].execution_code.classification == Classification::excluded_code);
  r.pre = kOther;
  assert(run(tx, r).sends[0].execution_code.classification == Classification::outside_registry);

  tx.out_msgs = {internal(address.c_str(), true)};
  assert(run(tx, r).sends.empty());
  tx.out_msgs = {internal("0:wrong")};
  assert(run(tx, r).sends.empty());
  tx.out_msgs = {external};
  r.pre = kV5;
  assert(run(tx, r).sends.size() == 1); // external-out alone

  // Premature StateInit does not prove deployment: status must be active, and VM
  // must attest successful message-state use and account activation.
  tx.orig_status = schema::uninit;
  tx.in_msg->destination = address;
  tx.end_status = schema::active;
  tx.in_msg->init_state = vm::CellBuilder().finalize(); // malformed/unapplied
  r.pre = kV5; // even a verified-looking pre-state hash cannot stand in for deployment
  r.post = kExcluded;
  auto premature = run(tx, r);
  assert(premature.sends[0].execution_code.classification == Classification::pending);
  assert(premature.active_witnesses[0].activation_candidate);
  assert(premature.active_witnesses[0].tx.pre_state_hash_hex == tx.account_state_hash_before.to_hex());
  assert(premature.active_witnesses[0].tx.post_state_hash_hex == tx.account_state_hash_after.to_hex());
  assert(premature.active_witnesses[0].post_state_hash_hex == premature.active_witnesses[0].tx.post_state_hash_hex);
  assert(premature.active_witnesses[0].tx.pre_state_hash_hex != premature.active_witnesses[0].tx.post_state_hash_hex);
  assert(premature.active_witnesses[0].post_code.classification == Classification::excluded_code);
  assert(!premature.active_witnesses[0].post_code.wallet_type_id);
  tx.orig_status = schema::nonexist;
  auto earlier = run(tx, r);
  assert(!earlier.active_witnesses[0].activation_candidate); // later uninit -> active is NOT first

  // VM's applied-init flags identify execution code on a first deployment;
  // merely attaching StateInit above did not. Post-code may be different.
  tx.orig_status = schema::uninit;
  auto code = vm::CellBuilder().finalize();
  vm::CellBuilder init;
  assert(init.store_long_bool(0, 1) && init.store_long_bool(0, 1) &&
         init.store_long_bool(1, 1) && init.store_ref_bool(code) &&
         init.store_long_bool(0, 1) && init.store_long_bool(0, 1));
  tx.in_msg->init_state = init.finalize();
  auto& ord = std::get<schema::TransactionDescr_ord>(tx.description);
  schema::TrComputePhase_vm vm{};
  vm.success = true;
  vm.msg_state_used = true;
  vm.account_activated = true;
  ord.compute_ph = vm;
  ord.aborted = false;
  auto applied = run(tx, r);
  assert(applied.sends[0].execution_code.classification == Classification::outside_registry);
  assert(applied.sends[0].execution_code.code_hash_hex &&
         bits(applied.sends[0].execution_code.code_hash_hex->c_str()) ==
             td::Bits256(code->get_hash().bits()));
  assert(applied.sends[0].execution_code.source == "applied_message_state_init:vm_account_activated");
  assert(applied.active_witnesses[0].post_code.classification == Classification::excluded_code);
  tx.in_msg->bounced = true;
  assert(run(tx, r).sends[0].execution_code.classification == Classification::pending);
  tx.in_msg->bounced = false;
  vm.account_activated = false;
  ord.compute_ph = vm;
  assert(run(tx, r).sends[0].execution_code.classification == Classification::pending);

  // Without the historical cell the concrete default resolver never falls back
  // to a current account or to the opposite endpoint's code.
  tx.orig_status = schema::active;
  tx.end_status = schema::active;
  auto reader = std::make_shared<CellReader>();
  CellDbVerifiedResolver historical(reader);
  assert(historical.resolve(tx, CodeUse::execution).resolution == Resolution::unavailable);
  auto root = account_cell(kAddress, code);
  tx.account_state_hash_before = td::Bits256(root->get_hash().bits());
  reader->cells[root->get_hash().as_slice().str()] = root;
  auto verified_pre = historical.resolve(tx, CodeUse::execution);
  assert(verified_pre.verified && verified_pre.resolution == Resolution::resolved);
  assert(verified_pre.code_hash == td::Bits256(code->get_hash().bits()));
  assert(verified_pre.source == "cell_db_verified_pre_state");
  assert(historical.resolve(tx, CodeUse::post_state).resolution == Resolution::unavailable);
  tx.account_state_hash_after = tx.account_state_hash_before;
  auto verified_post = historical.resolve(tx, CodeUse::post_state);
  assert(verified_post.verified && verified_post.source == "cell_db_verified_committed_post_state");
  reader->cells[root->get_hash().as_slice().str()] = account_cell(kTxHash, code);
  assert(historical.resolve(tx, CodeUse::execution).resolution == Resolution::unsupported);
  auto uninit = account_cell(kAddress, code, false);
  tx.account_state_hash_before = td::Bits256(uninit->get_hash().bits());
  reader->cells[uninit->get_hash().as_slice().str()] = uninit;
  assert(historical.resolve(tx, CodeUse::execution).resolution == Resolution::unsupported);
  tx.account_state_hash_before = td::Bits256(root->get_hash().bits());
  vm::CellBuilder absent;
  assert(absent.store_long_bool(0, 1));
  reader->cells[root->get_hash().as_slice().str()] = absent.finalize();
  assert(historical.resolve(tx, CodeUse::execution).resolution == Resolution::unsupported);
  assert(CellDbVerifiedResolver(nullptr).resolve(tx, CodeUse::execution).resolution == Resolution::unavailable);

  auto m = mc();
  auto s = shard();
  s.transactions.push_back(tx);
  bool rejected = false;
  try { extract_included({m, s, s}, {-1, m.shard, 10, m.root_hash, m.file_hash}, r); }
  catch (const std::invalid_argument&) { rejected = true; }
  assert(rejected); // repeated shard tip is NOT an additional set of wallet events
}
} // namespace

int main() { regressions(); }
