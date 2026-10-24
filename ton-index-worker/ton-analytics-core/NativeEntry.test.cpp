#ifdef NDEBUG
#undef NDEBUG
#endif
#include "AnchorEvidence.h"
#include "common/checksum.h"
#include "crypto/vm/cells/CellBuilder.h"
#include <cassert>
#include <stdexcept>

namespace {
ton::BlockIdExt id(int wc, uint32_t seqno, const char* label) {
  const auto value = std::string(label);
  return {wc, ton::shardIdAll, seqno, td::sha256_bits256(value + "-root"),
          td::sha256_bits256(value + "-file")};
}
bool has(const std::vector<tonstat::core::Issue>& issues, const std::string& code) {
  for (const auto& i : issues) if (i.code == code) return true;
  return false;
}
} // namespace

int main() {
  using namespace tonstat::core;
  const auto mc_id = id(-1, 11, "mc");
  NetworkPin pin{*testing::trusted_mc0(-239)};
  schema::MasterchainBlockDataState empty;
  auto missing = verify_anchor(empty, mc_id, pin);
  assert(missing.evidence->status == Status::incomplete && has(missing.evidence->issues, "missing_mc"));
  assert(missing.evidence->continuity_status == Status::incomplete &&
         !missing.evidence->snapshot_integrity_checked);
  assert(!missing.view && !missing.evidence->mc_signatures_checked);
  empty.shard_blocks_.emplace_back();
  auto malformed = verify_anchor(empty, mc_id, pin);
  assert(malformed.evidence->status == Status::incomplete && !malformed.view);
  assert(has(malformed.evidence->issues, "unresolved_input"));
  pin.zerostate = id(0, 0, "invalid-basechain-zero");
  malformed = verify_anchor(empty, mc_id, pin);
  assert(malformed.evidence->status == Status::error);
  assert(!malformed.evidence->cryptographic_zerostate_link_checked);
  schema::BlockDataState absent;
  const auto zero = *testing::trusted_mc0(-239);
  auto zero_aux = verify_auxiliary_mc(absent, zero, NetworkPin{zero});
  assert(zero_aux->status == Status::incomplete && has(zero_aux->issues, "unsupported_mc0_zerostate"));
  auto zero_snapshot = verify_anchor(empty, zero, NetworkPin{zero});
  assert(zero_snapshot.evidence->status == Status::incomplete &&
         has(zero_snapshot.evidence->issues, "unsupported_mc0_zerostate"));
  auto missing_aux = verify_auxiliary_mc(absent, mc_id, NetworkPin{*testing::trusted_mc0(-239)});
  assert(missing_aux->status == Status::incomplete && has(missing_aux->issues, "unresolved_input"));
  auto aux = verify_auxiliary_mc(absent, mc_id, pin);
  assert(aux->status == Status::error && !aux->mc_signatures_checked);
  vm::CellBuilder valid_empty, malformed_leaf, no_dict;
  valid_empty.store_long(0, 1); // HashmapE = empty
  malformed_leaf.store_long(1, 1); // claims a nonempty dict, but has no ref
  assert(testing::valid_shard_hashes(vm::load_cell_slice_ref(valid_empty.finalize())));
  assert(!testing::valid_shard_hashes(vm::load_cell_slice_ref(malformed_leaf.finalize())));
  assert(!testing::valid_shard_hashes(vm::load_cell_slice_ref(no_dict.finalize())));

  // Actual native exotic cells, not caller-attested booleans: reproduces the
  // September pilot failure and exercises the production update decoder.
  const auto before = vm::CellBuilder().store_long(11, 32).finalize();
  const auto after = vm::CellBuilder().store_long(12, 32).finalize();
  const auto update = vm::CellBuilder::create_merkle_update(before, after);
  bool ordinary_loader_rejected = false;
  try { (void)vm::load_cell_slice(update); }
  catch (const vm::VmError&) { ordinary_loader_rejected = true; }
  assert(ordinary_loader_rejected);
  const auto hashes = testing::state_update_hashes(update);
  assert(hashes.first == before->get_hash(0).as_bits256());
  assert(hashes.second == after->get_hash(0).as_bits256());
  assert(hashes.first != hashes.second);

  // An ordinary cell with byte-identical contents/refs is not a Merkle update.
  bool special = false;
  auto raw = vm::load_cell_slice_special(update, special);
  auto lookalike = vm::CellBuilder().append_cellslice(raw).finalize();
  for (const td::Ref<vm::Cell>& bad : {td::Ref<vm::Cell>(), td::Ref<vm::Cell>(before),
                                    td::Ref<vm::Cell>(lookalike)}) {
    bool rejected = false;
    try { (void)testing::state_update_hashes(bad); }
    catch (const std::runtime_error&) { rejected = true; }
    assert(rejected);
  }
}
