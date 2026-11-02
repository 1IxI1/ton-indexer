#include "ElectorSnapshotsStorage.h"

#include "clickhouse/columns/array.h"
#include "clickhouse/columns/date.h"
#include "clickhouse/columns/decimal.h"
#include "clickhouse/columns/nullable.h"
#include "clickhouse/columns/numeric.h"
#include "clickhouse/columns/string.h"
#include "clickhouse/columns/tuple.h"

namespace staking_history::clickhouse_storage {
namespace {
using namespace clickhouse;

void append_amount(ColumnDecimal& column, const td::RefInt256& value) {
  if (value.is_null() || !value->is_valid() || value->sgn() < 0 || value->to_dec_string().size() > 38) {
    throw std::runtime_error("Invalid stake amount");
  }
  column.Append(value->to_dec_string());
}

std::shared_ptr<ColumnTuple> positions_column(const std::vector<schema::FrozenPosition>& rows) {
  auto pubkey = std::make_shared<ColumnString>();
  auto holder = std::make_shared<ColumnString>();
  auto weight = std::make_shared<ColumnUInt64>();
  auto stake = std::make_shared<ColumnDecimal>(38, 0);
  auto banned = std::make_shared<ColumnUInt8>();
  auto adnl = std::make_shared<ColumnNullableT<ColumnString>>();
  for (const auto& p : rows) {
    pubkey->Append(p.pubkey);
    holder->Append(p.holder);
    weight->Append(p.weight);
    append_amount(*stake, p.stake);
    banned->Append(p.banned);
    adnl->Append(p.adnl);
  }
  return std::make_shared<ColumnTuple>(std::vector<ColumnRef>{pubkey, holder, weight, stake, banned, adnl});
}

std::shared_ptr<ColumnTuple> elections_column(const std::vector<schema::FrozenElection>& rows) {
  auto id = std::make_shared<ColumnUInt32>();
  auto hash = std::make_shared<ColumnString>();
  auto unfreeze = std::make_shared<ColumnUInt32>();
  auto held = std::make_shared<ColumnUInt32>();
  auto total = std::make_shared<ColumnDecimal>(38, 0);
  auto positions = std::make_shared<ColumnArray>(positions_column({}));
  for (const auto& e : rows) {
    id->Append(e.election_id);
    hash->Append(e.vset_hash);
    unfreeze->Append(e.unfreeze_at);
    held->Append(e.stake_held);
    append_amount(*total, e.total_stake);
    positions->AppendAsColumn(positions_column(e.positions));
  }
  return std::make_shared<ColumnTuple>(std::vector<ColumnRef>{id, hash, unfreeze, held, total, positions});
}

std::shared_ptr<ColumnTuple> participants_column(const std::vector<schema::ValidatorElectionParticipant>& rows) {
  auto pubkey = std::make_shared<ColumnString>();
  auto holder = std::make_shared<ColumnString>();
  auto adnl = std::make_shared<ColumnString>();
  auto stake = std::make_shared<ColumnDecimal>(38, 0);
  auto factor = std::make_shared<ColumnUInt32>();
  for (const auto& p : rows) {
    pubkey->Append(p.validator_pubkey);
    holder->Append(p.stake_holder_address);
    adnl->Append(p.adnl_addr);
    append_amount(*stake, p.stake);
    factor->Append(p.max_factor);
  }
  return std::make_shared<ColumnTuple>(std::vector<ColumnRef>{pubkey, holder, adnl, stake, factor});
}

std::shared_ptr<ColumnTuple> applications_column(const schema::ValidatorElection* a) {
  auto id = std::make_shared<ColumnUInt32>();
  auto close = std::make_shared<ColumnUInt32>();
  auto minimum = std::make_shared<ColumnDecimal>(38, 0);
  auto total = std::make_shared<ColumnDecimal>(38, 0);
  auto finished = std::make_shared<ColumnUInt8>();
  auto failed = std::make_shared<ColumnUInt8>();
  auto participants = std::make_shared<ColumnArray>(participants_column({}));
  if (a) {
    id->Append(a->election_id);
    close->Append(a->elect_close);
    append_amount(*minimum, a->min_stake);
    append_amount(*total, a->total_stake);
    finished->Append(a->finished);
    failed->Append(a->failed);
    participants->AppendAsColumn(participants_column(a->participants));
  }
  return std::make_shared<ColumnTuple>(std::vector<ColumnRef>{id, close, minimum, total, finished, failed, participants});
}
}  // namespace

clickhouse::Block states_block(const std::vector<schema::ElectorSnapshot>& states) {
  auto mc = std::make_shared<ColumnUInt32>();
  auto time = std::make_shared<ColumnDateTime>("UTC");
  auto address = std::make_shared<ColumnString>();
  auto code = std::make_shared<ColumnString>();
  auto data = std::make_shared<ColumnString>();
  auto previous = std::make_shared<ColumnString>();
  auto complete = std::make_shared<ColumnUInt8>();
  auto penalty = std::make_shared<ColumnUInt8>();
  auto error = std::make_shared<ColumnString>();
  auto applications_complete = std::make_shared<ColumnUInt8>();
  auto applications_error = std::make_shared<ColumnString>();
  auto elections = std::make_shared<ColumnArray>(elections_column({}));
  auto applications = std::make_shared<ColumnArray>(applications_column(nullptr));
  for (const auto& s : states) {
    mc->Append(s.mc_seqno);
    time->AppendRaw(s.gen_utime);
    address->Append(s.address);
    code->Append(s.code_hash);
    data->Append(s.data_hash);
    previous->Append(s.previous_data_hash);
    complete->Append(s.complete);
    penalty->Append(s.penalty_activity);
    error->Append(s.error);
    applications_complete->Append(s.applications_complete);
    applications_error->Append(s.applications_error);
    elections->AppendAsColumn(s.complete ? elections_column(s.elections) : elections_column({}));
    applications->AppendAsColumn(applications_column(s.applications_complete && s.applications ? &*s.applications : nullptr));
  }
  Block block;
  block.AppendColumn("mc_seqno", mc);
  block.AppendColumn("gen_utime", time);
  block.AppendColumn("elector_address", address);
  block.AppendColumn("code_hash", code);
  block.AppendColumn("data_hash", data);
  block.AppendColumn("previous_data_hash", previous);
  block.AppendColumn("complete", complete);
  block.AppendColumn("penalty_activity", penalty);
  block.AppendColumn("error", error);
  block.AppendColumn("applications_complete", applications_complete);
  block.AppendColumn("applications_error", applications_error);
  block.AppendColumn("elections", elections);
  block.AppendColumn("applications", applications);
  return block;
}

clickhouse::Block holders_block(const std::vector<schema::StakeHolder>& rows) {
  auto account = std::make_shared<ColumnString>();
  auto mc = std::make_shared<ColumnUInt32>();
  auto time = std::make_shared<ColumnDateTime>("UTC");
  auto code = std::make_shared<ColumnString>();
  auto data = std::make_shared<ColumnString>();
  auto kind = std::make_shared<ColumnString>();
  auto pool = std::make_shared<ColumnNullableT<ColumnString>>();
  auto error = std::make_shared<ColumnString>();
  for (const auto& h : rows) {
    account->Append(h.address);
    mc->Append(h.mc_seqno);
    time->AppendRaw(h.gen_utime);
    code->Append(h.code_hash);
    data->Append(h.data_hash);
    kind->Append(h.kind);
    pool->Append(h.pool);
    error->Append(h.error);
  }
  Block block;
  block.AppendColumn("account", account);
  block.AppendColumn("mc_seqno", mc);
  block.AppendColumn("gen_utime", time);
  block.AppendColumn("code_hash", code);
  block.AppendColumn("data_hash", data);
  block.AppendColumn("kind", kind);
  block.AppendColumn("pool", pool);
  block.AppendColumn("error", error);
  return block;
}

void insert_states(clickhouse::Client& client, const std::vector<InsertTaskStruct>& tasks) {
  std::vector<schema::ElectorSnapshot> snapshots;
  std::vector<schema::StakeHolder> holders;
  auto mc = std::make_shared<ColumnUInt32>();
  auto time = std::make_shared<ColumnDateTime>("UTC");
  auto hash = std::make_shared<ColumnString>();
  auto boc = std::make_shared<ColumnString>();
  for (const auto& task : tasks) {
    if (const auto& s = task.parsed_block_->elector_snapshot_) {
      if (s->mc_seqno != task.mc_seqno_) throw std::runtime_error("Elector MC mismatch");
      snapshots.push_back(*s);
    }
    if (const auto& s = task.parsed_block_->validator_set_state_) {
      if (s->mc_seqno != task.mc_seqno_) throw std::runtime_error("Validator set MC mismatch");
      mc->Append(s->mc_seqno);
      time->AppendRaw(s->gen_utime);
      hash->Append(s->config_hash);
      boc->Append(s->config_boc);
    }
    for (const auto& h : task.parsed_block_->stake_holder_states_) {
      if (h.mc_seqno != task.mc_seqno_) throw std::runtime_error("Holder MC mismatch");
      holders.push_back(h);
    }
  }
  if (!snapshots.empty()) client.Insert("elector_stake_states", states_block(snapshots));
  if (!holders.empty()) client.Insert("stake_holder_states", holders_block(holders));
  if (mc->Size()) {
    Block block;
    block.AppendColumn("mc_seqno", mc);
    block.AppendColumn("gen_utime", time);
    block.AppendColumn("config_hash", hash);
    block.AppendColumn("config_boc", boc);
    client.Insert("validator_set_states", block);
  }
}
}  // namespace staking_history::clickhouse_storage
