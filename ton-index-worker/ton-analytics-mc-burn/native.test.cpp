// Native linked in-memory fixture; requires pinned TON, no archive or network.
#define MC_BURN_UNIT_TEST
#include "main.cpp"
#include "crypto/vm/boc.h"
#include "crypto/vm/cells/CellBuilder.h"
#include "validator/fabric.h"
#include <functional>

namespace {
class RawFixture final : public ton::validator::BlockData {
 public:
  RawFixture(ton::BlockIdExt id, td::Ref<vm::Cell> root, std::string bytes)
      : id_(id), root_(std::move(root)), bytes_(std::move(bytes)) {}
  td::BufferSlice data() const override { return td::BufferSlice(bytes_); }
  ton::FileHash file_hash() const override { return id_.file_hash; }
  ton::BlockIdExt block_id() const override { return id_; }
  td::Ref<vm::Cell> root_cell() const override { return root_; }
 private:
  ton::BlockIdExt id_;
  td::Ref<vm::Cell> root_;
  std::string bytes_;
};
void rejects(const std::function<void()>& f) {
  bool failed=false;
  try { f(); } catch (const std::runtime_error&) { failed=true; }
  burn::need(failed,"negative native fixture unexpectedly accepted");
}
} // namespace

int main(int argc,char** argv) {
  burn::need(argc==2,"native fixture requires frozen 31-boundary pins path");
  auto pins=burn::parse_pins(burn::read(argv[1],16384));
  burn::need(pins.days.size()==31 && pins.days.front().first.id.seqno==89799586 &&
    pins.days.back().first.id.seqno==96135401,"real V3 frozen midnight pins failed to parse");
  auto root=vm::CellBuilder().store_long(42,8).finalize();
  auto boc=burn::ok(vm::std_boc_serialize(root),"serialize fixture");
  ton::BlockIdExt id{ton::masterchainId,ton::shardIdAll,123,
    root->get_hash().as_bits256(),td::sha256_bits256(boc.as_slice())};
  auto valid=burn::ok(ton::validator::create_block(id,boc.clone()),"valid fixture block");
  burn::need(burn::verify_original_boc(id,valid)->get_hash().as_bits256()==id.root_hash,
    "native fixture raw hash verification");
  auto bad_file=id; bad_file.file_hash=td::sha256_bits256("wrong original bytes");
  // BlockQ also rejects a bad ID during construction; our verification must
  // independently reject a metadata revision, not trust BlockData::file_hash().
  rejects([&] { burn::verify_original_boc(bad_file,valid); });
  td::Ref<RawFixture> tampered{true,id,root,"tampered original archived BoC"};
  td::Ref<ton::validator::BlockData> raw_tampered{tampered};
  rejects([&] { burn::verify_original_boc(id,raw_tampered); });
  auto other=vm::CellBuilder().store_long(43,8).finalize();
  auto wrong_root=id; wrong_root.root_hash=other->get_hash().as_bits256();
  rejects([&] { burn::verify_original_boc(wrong_root,valid); });
  td::Ref<RawFixture> forged_root{true,id,other,boc.as_slice().str()};
  td::Ref<ton::validator::BlockData> raw_root{forged_root};
  rejects([&] { burn::verify_original_boc(id,raw_root); });
  rejects([&] { burn::mainnet_id(-3); });
  burn::mainnet_id(-239);
  auto four=vm::CellBuilder().store_zeroes(20).finalize(); // four zero CurrencyCollections
  auto v1=vm::CellBuilder().store_long(0xb8e48dfb,32).store_ref(four)
      .store_zeroes(5).store_ref(four).finalize();
  burn::need(!burn::burned_value_flow(v1),"v1 absent burned must be null, not zero");
  auto v2=vm::CellBuilder().store_long(0x3ebf98b7,32).store_ref(four)
      .store_zeroes(5).store_long(1,4).store_long(123,8).store_zeroes(1).store_ref(four).finalize();
  burn::need(burn::burned_value_flow(v2)==std::optional<std::string>("123"),
    "v2 raw burned GRAM exact extraction");
  auto unknown=vm::CellBuilder().store_long(0xdeadbeef,32).finalize();
  rejects([&] { (void)burn::burned_value_flow(unknown); });
  std::cerr << "native MC burn in-memory hashes/network/v1-null/v2-burn fixture OK\n";
}
