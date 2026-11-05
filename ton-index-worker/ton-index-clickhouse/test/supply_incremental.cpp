#include "TotalSupply.h"
#include "TotalSupplyProcessor.h"
#include "../../tondb-scanner/test/smc-fixture.h"
#include "validator/fabric.h"
#include "validator/impl/shard.hpp"
#include "td/actor/TestScheduler.h"
#include "vm/cells/MerkleUpdate.h"

namespace {

using ton::BlockIdExt;
using ton::ShardIdFull;
using schema::BlockDataState;

BlockIdExt id_for(ShardIdFull shard, unsigned seqno) {
    return {shard.workchain, shard.shard, seqno, td::Bits256::zero(), td::Bits256::zero()};
}

class FixtureBlock final : public ton::validator::BlockData {
    BlockIdExt id_;
    td::Ref<vm::Cell> root_;
public:
    FixtureBlock(BlockIdExt id, td::Ref<vm::Cell> root) : id_(id), root_(std::move(root)) {}
    td::BufferSlice data() const override { return {}; }
    ton::FileHash file_hash() const override { return id_.file_hash; }
    BlockIdExt block_id() const override { return id_; }
    td::Ref<vm::Cell> root_cell() const override { return root_; }
};

td::Ref<vm::Cell> ext_ref(BlockIdExt id) {
    return vm::CellBuilder().store_zeroes(64).store_long(id.seqno(), 32)
        .store_bits(id.root_hash.bits(), 256).store_bits(id.file_hash.bits(), 256).finalize();
}

td::Ref<vm::Cell> dispatch_info(ShardIdFull shard, long long balance) {
    vm::AugmentedDictionary out{352, block::tlb::aug_OutMsgQueue};
    vm::CellBuilder info;
    info.append_cellslice(out.get_root()).store_long(0, 1);
    if (!balance) return info.store_long(0, 1).finalize();
    vm::CellBuilder msg;
    td::Bits256 address = td::Bits256::zero();
    address.bits().store_uint(shard.shard, 64);
    auto addr = test_address_cell(block::StdAddress(shard.workchain, address));
    msg.store_long(4, 4).append_cellslice(vm::load_cell_slice(addr));
    msg.append_cellslice(vm::load_cell_slice(addr));
    CHECK(block::CurrencyCollection{balance}.store(msg));
    msg.store_zeroes(4 + 4).store_long(1, 64).store_zeroes(32 + 1 + 1);
    td::Ref<vm::Cell> envelope;
    CHECK(block::tlb::t_MsgEnvelope.pack_cell(envelope,
        block::tlb::MsgEnvelope::Record_std{0, 0, td::zero_refint(), msg.finalize(), {}, {}}));
    block::AccountDispatchQueue account;
    CHECK(account.dict.set(td::BitArray<64>{1},
        vm::CellBuilder().store_long(1, 64).store_ref(envelope).as_cellslice_ref()));
    account.dict_size = 1;
    account.total_balance.invalidate();
    td::Ref<vm::CellSlice> packed;
    CHECK(account.pack(packed));
    vm::AugmentedDictionary dispatch{256, block::tlb::aug_DispatchQueue};
    CHECK(dispatch.set(address, packed));
    return info.store_long(1, 1).store_zeroes(4).append_cellslice(dispatch.get_root()).store_long(0, 1).finalize();
}

BlockDataState fixture(ShardIdFull shard, unsigned seqno, long long balance,
                       const std::vector<BlockDataState>& prev = {}, td::Ref<vm::Cell> custom = {}) {
    auto id = id_for(shard, seqno);
    td::Bits256 address = td::Bits256::zero();
    address.bits().store_uint(shard.shard, 64);
    block::gen::ShardStateUnsplit::Record state;
    auto empty = vm::CellBuilder().finalize();
    CHECK(tlb::unpack_cell(test_shard_with_account(block::StdAddress(shard.workchain, address), empty), state));
    vm::CellBuilder shard_cb;
    CHECK(block::ShardId{shard}.serialize(shard_cb));
    state.shard_id = shard_cb.as_cellslice_ref();
    state.seq_no = seqno;
    state.gen_utime = 1700000000 + seqno;
    state.out_msg_queue_info = dispatch_info(shard, balance);
    if (custom.not_null()) state.custom = vm::CellBuilder().store_long(1, 1).store_ref(custom).as_cellslice_ref();
    td::Ref<vm::Cell> root;
    CHECK(tlb::pack_cell(root, state));
    if (!seqno) {
        id.root_hash = root->get_hash().bits();
        return {td::Ref<FixtureBlock>{true, id, td::Ref<vm::Cell>{}}, root, {}};
    }
    vm::CellBuilder info;
    const bool split = prev.size() == 1 && prev[0].block_data->block_id().shard_full() != shard;
    info.store_long(0x9bc7a987, 32).store_zeroes(32).store_long(!shard.is_masterchain(), 1)
        .store_long(prev.size() == 2, 1).store_long(0, 1).store_long(split, 1).store_zeroes(4 + 8)
        .store_long(seqno, 32).store_zeroes(32).append_cellslice(shard_cb.as_cellslice_ref())
        .store_long(state.gen_utime, 32).store_long(1000, 64).store_long(2000, 64).store_zeroes(128);
    if (!shard.is_masterchain()) info.store_ref(ext_ref(id_for({ton::masterchainId, ton::shardIdAll}, 0)));
    auto previous = ext_ref(prev.empty() ? id_for(shard, seqno - 1) : prev[0].block_data->block_id());
    if (prev.size() == 2) previous = vm::CellBuilder().store_ref(previous).store_ref(ext_ref(prev[1].block_data->block_id())).finalize();
    info.store_ref(previous);
    vm::AugmentedDictionary out{256, block::tlb::aug_OutMsgDescrDefault};
    auto extra = vm::CellBuilder().store_long(0x4a33f6fd, 32).store_ref(empty)
        .store_ref(out.get_wrapped_dict_root()).store_ref(empty).store_zeroes(512 + 1).finalize();
    block::ValueFlow flow{block::ValueFlow::SetZero{}};
    vm::CellBuilder value_flow;
    CHECK(flow.store(value_flow));
    auto update = vm::CellBuilder::create_merkle_update(prev.empty() ? empty : prev[0].block_state, root);
    auto block_root = vm::CellBuilder().store_long(0x11ef55aa, 32).store_zeroes(32)
        .store_ref(info.finalize()).store_ref(value_flow.finalize()).store_ref(update).store_ref(extra).finalize();
    id.root_hash = block_root->get_hash().bits();
    return {td::Ref<FixtureBlock>{true, id, block_root}, root, {}};
}

td::Ref<vm::Cell> shard_tree(ShardIdFull shard, const std::vector<BlockDataState>& tips) {
    for (const auto& tip : tips) {
        if (tip.block_data->block_id().shard_full() != shard) continue;
        block::McShardHash desc{tip.block_data->block_id(), 0, 2000};
        desc.fees_collected_ = desc.funds_created_ = block::CurrencyCollection::zero();
        vm::CellBuilder cb;
        CHECK(cb.store_long_bool(0, 1) && desc.pack(cb));
        return cb.finalize();
    }
    CHECK(shard.pfx_len() < 2);
    return vm::CellBuilder().store_long(1, 1).store_ref(shard_tree(ton::shard_child(shard, true), tips))
        .store_ref(shard_tree(ton::shard_child(shard, false), tips)).finalize();
}

BlockDataState master(unsigned seqno, const std::vector<BlockDataState>& tips,
                      const std::vector<BlockDataState>& prev = {}, int version = 15) {
    vm::Dictionary validators{16};
    CHECK(validators.set(td::BitArray<16>::zero(), vm::CellBuilder().store_long(0x53, 8)
        .store_long(0x8e81278a, 32).store_zeroes(256).store_long(1, 64).as_cellslice_ref()));
    auto vset = vm::CellBuilder().store_long(0x12, 8).store_long(0, 32).store_long(2000000000, 32)
        .store_long(1, 16).store_long(1, 16).store_long(1, 64).append_cellslice(validators.get_root()).finalize();
    td::Ref<vm::Cell> config_root;
    test_smc_config(1700000000, {}, {{34, vset}, {8, vm::CellBuilder().store_long(0xc4, 8)
        .store_long(version, 32).store_zeroes(64).finalize()}}, &config_root);
    block::gen::ShardStateUnsplit::Record config_state;
    block::gen::McStateExtra::Record extra;
    CHECK(tlb::unpack_cell(config_root, config_state));
    CHECK(tlb::unpack_cell(config_state.custom->prefetch_ref(), extra));
    vm::Dictionary shards{32};
    if (!tips.empty()) {
        auto tree = shard_tree({0, ton::shardIdAll}, tips);
        CHECK(shards.set_ref(td::BitArray<32>::zero(), tree));
        CHECK(!shards.is_empty());
    }
    extra.shard_hashes = shards.get_root();
    vm::AugmentedDictionary old{32, block::tlb::aug_OldMcBlocksInfo};
    CHECK(old.set(td::BitArray<32>::zero(), vm::CellBuilder().store_long(1, 1)
        .append_cellslice(vm::load_cell_slice(ext_ref(id_for({-1, ton::shardIdAll}, 0)))).as_cellslice_ref()));
    extra.r1.prev_blocks = old.get_root();
    td::Ref<vm::Cell> custom;
    CHECK(tlb::pack_cell(custom, extra));
    auto result = fixture({-1, ton::shardIdAll}, seqno, 0, prev, custom);
    auto mc = ton::validator::MasterchainStateQ::fetch(result.block_data->block_id(), {}, result.block_state).move_as_ok();
    CHECK(mc->get_shards().size() == tips.size());
    return result;
}

schema::MasterchainBlockDataState bundle(BlockDataState mc, const std::vector<BlockDataState>& tips,
                                         const std::vector<BlockDataState>& intermediates = {}) {
    schema::MasterchainBlockDataState blocks;
    blocks.shard_blocks_.push_back(mc);
    for (const auto& tip : tips) if (tip.block_data->block_id().seqno()) blocks.shard_blocks_.push_back(tip);
    blocks.shard_blocks_diff_ = intermediates;
    blocks.shard_blocks_diff_.push_back(mc);
    return blocks;
}

gramstat::StateLoader no_load = [](BlockIdExt) -> td::actor::Task<td::Ref<ton::validator::ShardState>> {
    co_return td::Status::Error("Unexpected state load");
};

void same(const schema::TotalSupply& a, const schema::TotalSupply& b) {
    CHECK(a.mc_seqno == b.mc_seqno && a.gen_utime == b.gen_utime);
    CHECK(td::cmp(a.total, b.total) == 0 && td::cmp(a.accounts, b.accounts) == 0);
    CHECK(td::cmp(a.dispatch_queue, b.dispatch_queue) == 0 && td::cmp(a.unprocessed_messages, b.unprocessed_messages) == 0);
    CHECK(td::cmp(a.unrecovered_validator_fees, b.unrecovered_validator_fees) == 0);
}

td::actor::Task<gramstat::SupplyResult> verified(schema::MasterchainBlockDataState blocks,
                                               gramstat::SupplyCache previous = {}, gramstat::StateLoader loader = no_load) {
    auto incremental = co_await gramstat::calculate_incremental_supply(blocks, loader, std::move(previous)).wrap();
    LOG_CHECK(incremental.is_ok()) << incremental.error();
    auto result = incremental.move_as_ok();
    auto independent = co_await gramstat::calculate_total_supply(std::move(blocks), std::move(loader)).wrap();
    LOG_CHECK(independent.is_ok()) << independent.error();
    auto full = independent.move_as_ok();
    same(result.snapshot, full);
    co_return result;
}

void check_supply_cache() {
    const ShardIdFull shard{0, ton::shardIdAll};
    auto s1 = fixture(shard, 1, 100);
    auto s2 = fixture(shard, 2, 200, {s1});
    auto s3 = fixture(shard, 3, 300, {s2});
    auto mc1 = master(100, {s1});
    auto mc2 = master(101, {s3}, {mc1});
    auto mc3 = master(102, {s3}, {mc2});
    td::actor::TestScheduler scheduler;
    bool finished = false;
    scheduler.run([&]() -> td::actor::Task<> {
        auto first = co_await verified(bundle(mc1, {s1}));
        CHECK(first.stats.cold == 2 && first.cache.states.size() == 2);
        auto missing = co_await gramstat::calculate_incremental_supply(bundle(mc2, {s3}), no_load, first.cache).wrap();
        CHECK(missing.is_error());
        auto second = co_await verified(bundle(mc2, {s3}, {s2}), first.cache);
        CHECK(second.stats.cold == 0 && second.stats.with_prev == 3 && second.cache.states.size() == 2);
        CHECK(td::cmp(second.snapshot.dispatch_queue, 300) == 0);
        auto third = co_await verified(bundle(mc3, {s3}), second.cache);
        CHECK(third.stats.cold == 0 && third.stats.with_prev == 1 && third.cache.states.size() == 2);
        co_await verified(bundle(mc3, {s3}), third.cache);  // repeated anchor
        co_await verified(bundle(mc2, {s3}, {s2}), first.cache);  // prior cache survived the failure and successes
        auto restarted = co_await verified(bundle(mc2, {s3}, {s2}));
        CHECK(restarted.stats.cold == 2 && restarted.stats.with_prev == 0);
        auto version_mc = master(103, {s3}, {mc3}, 16);
        auto version = co_await verified(bundle(version_mc, {s3}), third.cache);
        CHECK(version.stats.reset_reason == "version" && version.stats.cold == 2);
        auto gap = co_await verified(bundle(master(110, {s3}), {s3}), third.cache);
        CHECK(gap.stats.reset_reason == "gap");
        auto wrong_mc = master(101, {s3});
        CHECK((co_await gramstat::calculate_incremental_supply(bundle(wrong_mc, {s3}, {s2}), no_load, first.cache).wrap()).is_error());
        auto bad = bundle(mc3, {s3});
        bad.shard_blocks_.back().block_state = s2.block_state;
        CHECK((co_await gramstat::calculate_incremental_supply(bad, no_load, second.cache).wrap()).is_error());
        auto left = fixture(ton::shard_child(shard, true), 2, 40, {s1});
        auto right = fixture(ton::shard_child(shard, false), 2, 60, {s1});
        auto split_mc = master(101, {left, right}, {mc1});
        auto split = co_await verified(bundle(split_mc, {left, right}), first.cache);
        CHECK(split.cache.states.size() == 3 && split.stats.cold == 0);
        auto merged = fixture(shard, 3, 100, {left, right});
        auto merge = co_await verified(bundle(master(102, {merged}, {split_mc}), {merged}), split.cache);
        CHECK(merge.cache.states.size() == 2 && merge.stats.cold == 0);
        auto zero = fixture(shard, 0, 0);
        auto load_zero = [zero](BlockIdExt id) -> td::actor::Task<td::Ref<ton::validator::ShardState>> {
            CHECK(id == zero.block_data->block_id());
            co_return co_await ton::validator::create_shard_state(id, zero.block_state);
        };
        auto zerostate = co_await verified(bundle(master(100, {zero}), {zero}), {}, load_zero);
        CHECK(zerostate.cache.states.size() == 2);
        finished = true;
        co_return td::Unit{};
    });
    CHECK(finished);
}

void check_supply_ordering() {
    td::actor::TestScheduler scheduler;
    bool finished = false;
    scheduler.run([&]() -> td::actor::Task<> {
        auto processor = td::actor::create_actor<gramstat::TotalSupplyProcessor>("supply_test", 10, 8);
        std::vector<unsigned> calls;
        auto request = [&](unsigned seqno, bool fail, unsigned expected_prev) {
            auto id = id_for({-1, ton::shardIdAll}, seqno);
            gramstat::SupplyCalculation calculate = [&, id, fail, expected_prev](gramstat::SupplyCache previous)
                -> td::actor::Task<gramstat::SupplyResult> {
                CHECK((expected_prev == 0 && previous.global_version == -1) || previous.mc_id.seqno() == expected_prev);
                calls.push_back(id.seqno());
                if (fail) co_return td::Status::Error("Transient test failure");
                gramstat::SupplyResult result;
                result.cache.mc_id = id;
                result.cache.global_version = 15;
                ton::validator::GlobalBalanceComponents c;
                result.snapshot = co_await gramstat::make_total_supply(id.seqno(), 1700000000 + id.seqno(), c);
                co_return result;
            };
            return td::actor::ask(processor, &gramstat::TotalSupplyProcessor::submit, id, std::move(calculate));
        };
        auto later = request(12, false, 11);
        auto middle = request(11, false, 10);
        auto failed = request(10, true, 0);
        auto duplicate = request(10, true, 0);
        CHECK((co_await std::move(failed).wrap()).is_error());
        CHECK((co_await std::move(duplicate).wrap()).is_error());
        CHECK(calls == std::vector<unsigned>{10});
        auto retry = request(10, false, 0);
        CHECK((co_await std::move(retry)).mc_seqno == 10);
        CHECK((co_await std::move(middle)).mc_seqno == 11);
        CHECK((co_await std::move(later)).mc_seqno == 12);
        CHECK((calls == std::vector<unsigned>{10, 10, 11, 12}));
        auto cached = request(10, true, 999);  // calculator must not run
        CHECK((co_await std::move(cached)).mc_seqno == 10 && calls.size() == 4);
        td::actor::send_closure(processor, &gramstat::TotalSupplyProcessor::forget, 10);
        auto old = request(10, false, 0);
        CHECK((co_await std::move(old)).mc_seqno == 10);
        auto forward = request(13, false, 12);  // late retry did not roll back the cache
        CHECK((co_await std::move(forward)).mc_seqno == 13);
        auto pending = request(15, false, 14);
        processor.reset();
        CHECK((co_await std::move(pending).wrap()).is_error());
        finished = true;
        co_return td::Unit{};
    });
    CHECK(finished);
}

}  // namespace

void check_incremental_supply() {
    check_supply_cache();
    check_supply_ordering();
}
