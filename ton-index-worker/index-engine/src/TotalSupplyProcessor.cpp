#include "TotalSupplyProcessor.h"
#include "Statistics.h"

namespace gramstat {
namespace {

// Own the callable until its coroutine finishes, including actor shutdown.
td::actor::Task<SupplyResult> run_calculation(SupplyCalculation calculate, SupplyCache cache) {
    co_return co_await calculate(std::move(cache));
}

}  // namespace

void TotalSupplyProcessor::submit(ton::BlockIdExt id, SupplyCalculation calculate,
                                  td::Promise<schema::TotalSupply> promise) {
    if (!id.is_masterchain() || !calculate) {
        promise.set_error(td::Status::Error("Invalid total supply request"));
        return;
    }
    auto done = completed_.find(id.seqno());
    if (done != completed_.end()) {
        if (done->second.id != id) promise.set_error(td::Status::Error("Total supply retry block ID mismatch"));
        else {
            g_statistics.record_count(SUPPLY_RESULT_CACHE_HIT);
            promise.set_value(schema::TotalSupply(done->second.snapshot));
        }
        return;
    }
    auto [it, inserted] = pending_.try_emplace(id.seqno(), Request{id, std::move(calculate), {}});
    if (!inserted && it->second.id != id) {
        promise.set_error(td::Status::Error("Conflicting pending total supply block IDs"));
        return;
    }
    it->second.promises.push_back(std::move(promise));
    drain();
}

void TotalSupplyProcessor::drain() {
    if (busy_ || pending_.empty() || pending_.begin()->first > next_seqno_) return;
    auto& request = pending_.begin()->second;
    auto seqno = request.id.seqno();
    busy_ = true;
    auto promise = td::PromiseCreator::lambda([self = actor_id(this), seqno](td::Result<SupplyResult> result) {
        td::actor::send_closure(self, &TotalSupplyProcessor::finished, seqno, std::move(result));
    });
    // An old retry evicted from the result cache gets an isolated cold snapshot;
    // it must not replace the advancing cache or move the expected seqno back.
    td::connect(std::move(promise), run_calculation(request.calculate, seqno == next_seqno_ ? cache_ : SupplyCache{}));
}

void TotalSupplyProcessor::finished(std::uint32_t seqno, td::Result<SupplyResult> result) {
    auto request = std::move(pending_.at(seqno));
    pending_.erase(seqno);
    busy_ = false;
    if (result.is_ok() && (result.ok().cache.mc_id != request.id || result.ok().snapshot.mc_seqno != seqno)) {
        result = td::Status::Error("Total supply result does not match its request");
    }
    if (result.is_error()) {
        for (auto& promise : request.promises) promise.set_error(result.error().clone());
    } else {
        auto value = result.move_as_ok();
        if (seqno == next_seqno_) {
            cache_ = std::move(value.cache);
            ++next_seqno_;
        }
        completed_[seqno] = Completed{request.id, value.snapshot};
        while (completed_.size() > max_results_) completed_.erase(completed_.begin());
        const auto& stats = value.stats;
        const auto elapsed = stats.prepare_seconds + stats.compute_seconds;
        g_statistics.record_count(SUPPLY_STATE_REUSED, stats.reused);
        g_statistics.record_count(SUPPLY_STATE_COLD, stats.cold);
        g_statistics.record_count(SUPPLY_STATE_WITH_PREV, stats.with_prev);
        g_statistics.record_time(SUPPLY_PREPARE, stats.prepare_seconds * 1e6);
        g_statistics.record_time(SUPPLY_COMPUTE, stats.compute_seconds * 1e6);
        g_statistics.record_time(SUPPLY_TOTAL, elapsed * 1e6);
        if (stats.cold || elapsed >= 1.0 || seqno % 1000 == 0) {
            LOG(INFO) << "Total supply " << seqno << ": reused=" << stats.reused
                      << " cold=" << stats.cold << " with_prev=" << stats.with_prev
                      << " cached_tips=" << cache_.states.size() << " reset=" << stats.reset_reason
                      << " prepare=" << stats.prepare_seconds << " compute=" << stats.compute_seconds
                      << " total=" << elapsed;
        }
        for (auto& promise : request.promises) promise.set_value(schema::TotalSupply(value.snapshot));
    }
    drain();
}

void TotalSupplyProcessor::forget(std::uint32_t seqno) {
    completed_.erase(seqno);
}

void TotalSupplyProcessor::tear_down() {
    for (auto& [_, request] : pending_) {
        for (auto& promise : request.promises) {
            promise.set_error(td::Status::Error("Total supply processor stopped"));
        }
    }
    pending_.clear();
}

}  // namespace gramstat
