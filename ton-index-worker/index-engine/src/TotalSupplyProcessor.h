#pragma once

#include "TotalSupply.h"

namespace gramstat {

using SupplyCalculation = std::function<td::actor::Task<SupplyResult>(SupplyCache)>;

// Orders the supply stage independently of the parallel fetch/parse pipeline.
// The scheduler bounds outstanding submissions by max_active_tasks. Keep small
// completed results for insert retries; only one MC's prepared states survive.
class TotalSupplyProcessor : public td::actor::Actor {
public:
    explicit TotalSupplyProcessor(std::uint32_t first_seqno, std::size_t max_results = 1024)
        : next_seqno_(first_seqno), max_results_(max_results) {}

    void submit(ton::BlockIdExt id, SupplyCalculation calculate, td::Promise<schema::TotalSupply> promise);
    void forget(std::uint32_t seqno);
    void tear_down() override;

private:
    struct Request {
        ton::BlockIdExt id;
        SupplyCalculation calculate;
        std::vector<td::Promise<schema::TotalSupply>> promises;
    };
    struct Completed {
        ton::BlockIdExt id;
        schema::TotalSupply snapshot;
    };
    std::uint32_t next_seqno_;
    std::size_t max_results_;
    bool busy_ = false;
    SupplyCache cache_;
    std::map<std::uint32_t, Request> pending_;
    std::map<std::uint32_t, Completed> completed_;

    void drain();
    void finished(std::uint32_t seqno, td::Result<SupplyResult> result);
};

}  // namespace gramstat
