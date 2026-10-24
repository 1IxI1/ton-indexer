#include "AnchorEvidence.h"

#include "crypto/block/block.h"
#include "crypto/block/block-auto.h"
#include "crypto/block/block-parse.h"
#include "crypto/block/mc-config.h"
#include "crypto/vm/cells/MerkleUpdate.h"
#include "common/checksum.h"
#include "td/utils/crypto.h"

#include <map>
#include <set>
#include <stdexcept>
#include <utility>

namespace tonstat::core {
namespace testing {
std::pair<td::Bits256, td::Bits256> state_update_hashes(td::Ref<vm::Cell> root) {
  if (root.is_null() || vm::MerkleUpdate::validate(root).is_error())
    throw std::runtime_error("invalid raw Merkle state_update");
  // MERKLE_UPDATE is exotic by definition. The ordinary loader throws
  // "unexpected special cell" even after successful MerkleUpdate validation.
  // Match pinned TON validator/db/celldb-utils.cpp, never virtualize the update.
  bool special = false;
  auto update = vm::load_cell_slice_special(root, special);
  td::Bits256 old_hash, new_hash;
  if (!special || update.special_type() != vm::Cell::SpecialType::MerkleUpdate ||
      update.size() != 552 || update.size_refs() != 2 ||
      update.fetch_ulong(8) != 4 || !update.fetch_bits_to(old_hash.bits(), 256) ||
      !update.fetch_bits_to(new_hash.bits(), 256))
    throw std::runtime_error("malformed raw state_update hash fields");
  return {old_hash, new_hash};
}

bool valid_shard_hashes(td::Ref<vm::CellSlice> encoded) {
  return block::gen::t_ShardHashes.validate_csr(1 << 20, std::move(encoded));
}
} // namespace testing

namespace {

void require(bool condition, const char* description) {
  if (!condition) throw std::runtime_error(description);
}

struct MissingInput : std::runtime_error {
  using std::runtime_error::runtime_error;
};

void present(bool condition, const char* description) {
  if (!condition) throw MissingInput(description);
}

bool valid_mc(const ton::BlockIdExt& id) {
  return id.is_masterchain() && id.is_valid_full() && id.id.shard == ton::shardIdAll;
}

bool valid_pin(const NetworkPin& pin) {
  return valid_mc(pin.zerostate) && pin.zerostate.id.seqno == 0;
}

std::string network_for(int32_t id) {
  if (id == -239) return "mainnet";
  if (id == -3) return "testnet";
  return {}; // Unknown global IDs must never be silently relabelled.
}

struct Decoded {
  BlockEvidence evidence;
  td::Ref<vm::Cell> root;
};

Decoded decode(const schema::BlockDataState& entry, const ton::BlockIdExt& expected) {
  require(expected.is_valid_full(), "invalid expected full block ID");
  present(static_cast<bool>(entry.handle), "missing block handle");
  require(entry.handle->id() == expected, "handle full block ID mismatch");
  present(entry.block_data.not_null(), "missing original block BoC");
  require(entry.block_data->block_id() == expected, "BlockData full block ID mismatch");
  present(entry.block_state.not_null(), "missing post-state root");
  // BlockData::file_hash() merely echoes metadata. Hash the ORIGINAL bytes.
  auto bytes = entry.block_data->data();
  present(!bytes.empty(), "original block BoC bytes unavailable");
  require(td::sha256_bits256(bytes.as_slice()) == expected.file_hash,
          "original block BoC SHA-256 differs from full ID file hash");
  auto root = entry.block_data->root_cell();
  present(root.not_null(), "raw block root unavailable");
  require(root->get_hash().as_bits256() == expected.root_hash,
          "raw block representation hash differs from full ID root hash");
  block::gen::Block::Record raw;
  block::gen::BlockInfo::Record info;
  require(tlb::unpack_cell(root, raw) && tlb::unpack_cell(raw.info, info),
          "malformed raw Block or BlockInfo");
  require(info.seq_no == expected.id.seqno && info.not_master == !expected.is_masterchain(),
          "raw BlockInfo seqno/masterchain flag differs from full ID");
  require(info.shard.not_null(), "missing raw BlockInfo shard");
  const block::ShardId raw_shard(info.shard);
  require(raw_shard.is_valid() && raw_shard.workchain_id == expected.id.workchain &&
              raw_shard.shard_pfx == expected.id.shard, "raw BlockInfo shard differs from full ID");
  const auto [old_hash, new_hash] = testing::state_update_hashes(raw.state_update);
  auto hashes = testing::check_block_hashes(bytes.as_slice(), expected, root->get_hash().as_bits256(),
                                             new_hash, entry.block_state->get_hash().as_bits256());
  require(hashes.empty(), "raw BoC file/root hash or state_update.new_hash mismatch");
  // Decode actual ShardStateUnsplit semantics; root hashes alone say nothing
  // about the state identity/global network (nor a split-state root).
  block::gen::ShardStateUnsplit::Record state;
  require(tlb::unpack_cell(entry.block_state, state), "cannot decode raw ShardStateUnsplit");
  const block::ShardId state_shard(state.shard_id);
  require(state_shard.is_valid() && state_shard.workchain_id == expected.id.workchain &&
              state_shard.shard_pfx == expected.id.shard && state.seq_no == expected.id.seqno &&
              state.global_id == raw.global_id && state.gen_utime == info.gen_utime,
          "post-state workchain/shard/seqno/global ID/time differs from raw block");
  return {{expected, entry.block_state->get_hash().as_bits256(), old_hash, new_hash,
           raw.global_id, info.gen_utime}, std::move(root)};
}

void checked(AnchorEvidence& result, std::string code, std::string subject, std::string observed) {
  result.checks.push_back({std::move(code), std::move(subject), std::move(observed)});
}

void issue(AnchorEvidence& result, std::string code, std::string detail, Status status = Status::error) {
  if (status == Status::error || result.status != Status::error) result.status = status;
  result.issues.push_back({std::move(code), std::move(detail)});
}

// The root/file check is performed for *every* block passed to decode.
BlockEvidence decode_checked(AnchorEvidence& result, const schema::BlockDataState& entry,
                             const ton::BlockIdExt& expected) {
  auto decoded = decode(entry, expected);
  const auto id = expected.to_str();
  checked(result, "full_id_handle_block_data_and_original_boc_sha256", id, expected.file_hash.to_hex());
  checked(result, "raw_block_root_and_header", id, expected.root_hash.to_hex());
  checked(result, "merkle_update_new_equals_typed_post_state", id, decoded.evidence.state_root.to_hex());
  return decoded.evidence;
}

std::vector<ton::BlockIdExt> predecessors(const schema::BlockDataState& entry,
                                           const ton::BlockIdExt& id) {
  auto header = block::get_block_header_info(entry.block_data->root_cell(), id);
  require(header.is_ok(), "cannot decode raw full-ID MC predecessor");
  auto decoded = header.move_as_ok();
  require(decoded.prev.size() == 1 && !decoded.after_split && decoded.mc_blkid == decoded.prev.front() &&
              valid_mc(decoded.prev.front()), "MC header does not name exactly one valid full-ID predecessor");
  return decoded.prev;
}

std::vector<ton::BlockIdExt> mc_tips(const schema::BlockDataState& entry) {
  block::gen::ShardStateUnsplit::Record state;
  block::gen::McStateExtra::Record extra;
  block::ShardConfig shards;
  require(tlb::unpack_cell(entry.block_state, state) && state.custom.not_null() &&
               tlb::unpack_cell(state.custom->prefetch_ref(), extra),
          "cannot decode MC post-state ShardHashes");
  // ShardConfig::init only installs a dictionary; its enumerator returns an
  // empty vector on a malformed nonempty leaf. Validate every TL-B leaf first.
  require(testing::valid_shard_hashes(extra.shard_hashes),
          "malformed ShardHashes dictionary or leaf");
  require(shards.unpack(extra.shard_hashes), "cannot unpack validated ShardHashes");
  return shards.get_shard_hash_ids_ext(true); // true includes full root/file hashes AND seqno=0.
}

void pin_checks(AnchorEvidence& out) {
  require(valid_pin(out.pin), "missing or invalid pinned full-ID MC zerostate");
  const auto mainnet = testing::trusted_mc0(-239);
  const auto testnet = testing::trusted_mc0(-3);
  require((mainnet && out.pin.zerostate == *mainnet) ||
              (testnet && out.pin.zerostate == *testnet),
          "MC0 root/file is not a trusted mainnet or testnet identity");
}

void pin_against_mc_state(AnchorEvidence& out, const schema::BlockDataState& entry,
                          const BlockEvidence& source) {
  auto config = block::ConfigInfo::extract_config(entry.block_state, source.id);
  require(config.is_ok(), "cannot decode MC post-state config/OldMcBlocks zerostate");
  const auto zero = config.ok()->get_zerostate_id();
  const ton::BlockIdExt decoded{zero.workchain, ton::shardIdAll, 0, zero.root_hash, zero.file_hash};
  if (source.id == out.mc.id) out.mc_state_zerostate = decoded;
  auto problems = testing::check_network_pin(source.global_id, out.pin.zerostate, decoded);
  require(problems.empty(), "pinned MC0 or MC post-state OldMcBlocks MC0 differs from trusted network root/file");
  checked(out, "external_pin_and_mc_state_mc0_match_trusted_network", source.id.to_str(), decoded.to_str());
}

} // namespace

Outcome verify_anchor(const schema::MasterchainBlockDataState& input,
                      const ton::BlockIdExt& expected_mc, const NetworkPin& pin,
                      const std::vector<schema::BlockDataState>& extra_tips,
                      const schema::BlockDataState* previous,
                      std::shared_ptr<vm::CellDbReader> reader) {
  Outcome out;
  AnchorEvidence e;
  auto finish = [&]() {
    out.evidence = std::make_shared<const AnchorEvidence>(e);
    return out;
  };
  e.pin = pin;
  e.status = Status::incomplete;
  if (previous) e.continuity_reason = "adjacent_previous_mc_not_yet_verified";
  if (input.shard_blocks_.empty()) {
    issue(e, "missing_mc", "shard_blocks_ has no MC entry", Status::incomplete);
    return finish();
  }
  if (valid_mc(expected_mc) && expected_mc.id.seqno == 0) {
    issue(e, "unsupported_mc0_zerostate", "MC0 is a zerostate, not an ordinary block", Status::incomplete);
    return finish();
  }
  try {
    require(valid_mc(expected_mc) && expected_mc.id.seqno > 0,
            "externally selected non-genesis MC full ID invalid");
    pin_checks(e);
    const auto& mc = input.shard_blocks_.front();
    e.mc = decode_checked(e, mc, expected_mc);
    require(e.mc.id.is_masterchain(), "snapshot first entry is not MC");
    e.network = network_for(e.mc.global_id);
    require(!e.network.empty(), "unknown MC global ID/network");
    pin_against_mc_state(e, mc, e.mc);
    checked(e, "network_from_raw_mc_global_id", expected_mc.to_str(), e.network);
    e.mc_predecessors = predecessors(mc, expected_mc);
    checked(e, "raw_mc_header_full_predecessor", expected_mc.to_str(), e.mc_predecessors.front().to_str());
    e.expected_shard_tips = mc_tips(mc);
    checked(e, "tips_enumerated_from_mc_post_state", expected_mc.to_str(),
            std::to_string(e.expected_shard_tips.size()));
    std::map<ton::BlockIdExt, const schema::BlockDataState*> supplied;
    for (size_t i = 1; i < input.shard_blocks_.size(); ++i) {
      const auto& tip = input.shard_blocks_[i];
      present(static_cast<bool>(tip.handle), "missing scanner tip handle");
      require(supplied.emplace(tip.handle->id(), &tip).second,
              "duplicate scanner tip full ID");
    }
    for (const auto& tip : extra_tips) {
      present(static_cast<bool>(tip.handle), "missing separately fetched tip handle");
      require(supplied.emplace(tip.handle->id(), &tip).second,
              "duplicate separately fetched tip full ID");
    }
    std::set<ton::BlockIdExt> expected_set;
    for (const auto& id : e.expected_shard_tips) {
      require(id.is_valid_full() && !id.is_masterchain() && expected_set.insert(id).second,
              "invalid or duplicate MC ShardHashes full tip ID");
      if (id.id.seqno == 0)
        issue(e, "unsupported_zero_seqno_tip", id.to_str() + " requires distinct zerostate state/BoC verification",
              Status::incomplete);
    }
    if (!e.issues.empty()) return finish();
    for (const auto& [id, entry] : supplied) {
      require(expected_set.count(id) != 0, "unexpected scanner/extra tip full ID");
      e.shard_tips.push_back(decode_checked(e, *entry, id));
    }
    for (const auto& entry : input.shard_blocks_diff_) {
      present(static_cast<bool>(entry.handle), "missing first-included block handle");
      const auto id = entry.handle->id();
      if (!id.is_masterchain()) {
        require(id.id.seqno > 0 && entry.handle->inited_masterchain_ref_block() &&
                    entry.handle->masterchain_ref_block() == expected_mc.id.seqno,
                "diff shard block handle not first-included at this MC");
      }
      e.first_included.push_back(decode_checked(e, entry, id));
    }
    e.diff_handle_inclusion_checked = true; // still not an independent exhaustive ancestry proof
    for (const auto& problem : testing::check_relationships(
             e.mc, e.mc_predecessors, e.expected_shard_tips, e.shard_tips,
             e.first_included, std::nullopt)) {
      issue(e, problem.code, problem.detail,
            (problem.code == "missing_tip" || problem.code == "missing_mc_in_diff")
                ? Status::incomplete : Status::error);
    }
    if (!e.issues.empty()) return finish();
    e.snapshot_integrity_checked = true;
    std::optional<BlockEvidence> previous_decoded;
    if (previous) {
      e.continuity_reason = "adjacent_previous_mc_validation_failed";
      e.continuity_status = Status::error;
      present(static_cast<bool>(previous->handle), "missing adjacent MC predecessor handle");
      previous_decoded = decode_checked(e, *previous, previous->handle->id());
      require(previous_decoded->id.is_masterchain() &&
                  previous_decoded->global_id == e.mc.global_id,
              "adjacent predecessor is not MC or has different global ID");
      pin_against_mc_state(e, *previous, *previous_decoded);
      e.previous_mc = previous_decoded->id;
      e.previous_mc_state_root = previous_decoded->state_root;
      for (const auto& problem : testing::check_relationships(
               e.mc, e.mc_predecessors, e.expected_shard_tips, e.shard_tips,
               e.first_included, previous_decoded)) {
        issue(e, problem.code, problem.detail, Status::error);
      }
    }
    if (e.issues.empty()) {
      if (previous_decoded) {
        checked(e, "adjacent_mc_predecessor_full_id_and_state_update_old", expected_mc.to_str(),
                previous_decoded->id.to_str() + " / " + previous_decoded->state_root.to_hex());
        e.continuity_status = Status::verified_local_archive;
        e.continuity_reason.clear();
      }
      checked(e, "exact_mc_top_tip_full_id_set_including_zero", expected_mc.to_str(),
              std::to_string(e.shard_tips.size()));
      checked(e, "diff_unique_full_ids_and_contains_mc", expected_mc.to_str(),
              std::to_string(e.first_included.size()));
      e.status = Status::verified_local_archive;
      if (reader) {
        out.view = std::shared_ptr<const MaterializedAnchor>(
            new MaterializedAnchor(e, input, extra_tips, std::move(reader)));
      }
    }
  } catch (const MissingInput& ex) {
    issue(e, "unresolved_input", ex.what(), Status::incomplete);
  } catch (const vm::VmError& ex) {
    issue(e, "unreadable_cell", ex.get_msg(), Status::incomplete);
  } catch (const std::exception& ex) {
    issue(e, "invalid_archive_input", ex.what());
  }
  return finish();
}

std::shared_ptr<const AnchorEvidence> verify_auxiliary_mc(
    const schema::BlockDataState& entry, const ton::BlockIdExt& expected_mc, const NetworkPin& pin) {
  AnchorEvidence out;
  out.scope = Scope::auxiliary_mc_only;
  out.pin = pin;
  if (valid_mc(expected_mc) && expected_mc.id.seqno == 0) {
    issue(out, "unsupported_mc0_zerostate", "MC0 is a zerostate, not an ordinary block",
          Status::incomplete);
    return std::make_shared<const AnchorEvidence>(std::move(out));
  }
  try {
    require(valid_mc(expected_mc) && expected_mc.id.seqno > 0,
            "auxiliary non-genesis MC expected full ID invalid");
    pin_checks(out);
    out.mc = decode_checked(out, entry, expected_mc);
    out.network = network_for(out.mc.global_id);
    require(!out.network.empty(), "unknown auxiliary MC global ID/network");
    pin_against_mc_state(out, entry, out.mc);
    checked(out, "network_from_raw_mc_global_id", expected_mc.to_str(), out.network);
    out.mc_predecessors = predecessors(entry, expected_mc);
    checked(out, "raw_mc_header_full_predecessor", expected_mc.to_str(), out.mc_predecessors.front().to_str());
    out.status = Status::verified_local_archive;
    out.snapshot_integrity_checked = true; // local MC identity/state only, NOT a full tip snapshot
  } catch (const MissingInput& ex) {
    issue(out, "unresolved_input", ex.what(), Status::incomplete);
  } catch (const vm::VmError& ex) {
    issue(out, "unreadable_cell", ex.get_msg(), Status::incomplete);
  } catch (const std::exception& ex) {
    issue(out, "invalid_archive_input", ex.what());
  }
  return std::make_shared<const AnchorEvidence>(std::move(out));
}

} // namespace tonstat::core
