#include "ElectorSnapshotsPostgres.h"
#include "postgresql_tools.h"

void staking_history::postgres::insert_states(pqxx::work& txn, const std::vector<InsertTaskStruct>& tasks) {
  std::map<uint32_t, const schema::ElectorSnapshot*> states;
  for (const auto& task : tasks) {
    if (const auto& s = task.parsed_block_->elector_snapshot_) {
      if (s->mc_seqno != task.mc_seqno_) throw std::runtime_error("Elector MC mismatch");
      states[s->mc_seqno] = &*s;
    }
  }
  {
    std::initializer_list<std::string_view> columns = {
        "mc_seqno", "gen_utime", "elector_address", "code_hash", "data_hash", "previous_data_hash",
        "complete", "penalty_activity", "error", "applications_complete", "applications_error"};
    PopulateTableStream stream(txn, "public.elector_stake_states", columns, 100);
    stream.setConflictDoUpdate({"mc_seqno"}, "");
    for (const auto& [mc, s] : states) {
      stream.insert_row(std::make_tuple(mc, s->gen_utime, s->address, s->code_hash, s->data_hash,
          s->previous_data_hash, s->complete, s->penalty_activity, s->error,
          s->applications_complete, s->applications_error));
    }
    stream.finish();
  }
  // Replace complete child sets in the same transaction. Cascades also remove
  // positions/participants when a replay corrects a record to empty or unknown.
  for (const auto& [mc, s] : states) {
    txn.exec0("DELETE FROM public.elector_frozen_elections WHERE mc_seqno=" + std::to_string(mc));
    txn.exec0("DELETE FROM public.elector_applications WHERE mc_seqno=" + std::to_string(mc));
  }
  {
    std::initializer_list<std::string_view> columns = {
        "mc_seqno", "election_id", "vset_hash", "unfreeze_at", "stake_held", "total_stake"};
    PopulateTableStream stream(txn, "public.elector_frozen_elections", columns, 100);
    for (const auto& [mc, s] : states) {
      if (!s->complete) continue;
      for (const auto& e : s->elections) {
        stream.insert_row(std::make_tuple(mc, e.election_id, e.vset_hash, e.unfreeze_at, e.stake_held, e.total_stake));
      }
    }
    stream.finish();
  }
  {
    std::initializer_list<std::string_view> columns = {
        "mc_seqno", "election_id", "pubkey", "holder", "weight", "stake", "banned", "adnl"};
    PopulateTableStream stream(txn, "public.elector_stake_positions", columns, 1000);
    for (const auto& [mc, s] : states) {
      if (!s->complete) continue;
      for (const auto& e : s->elections) {
        for (const auto& p : e.positions) {
          stream.insert_row(std::make_tuple(mc, e.election_id, p.pubkey, p.holder, p.weight, p.stake, p.banned, p.adnl));
        }
      }
    }
    stream.finish();
  }
  {
    std::initializer_list<std::string_view> columns = {
        "mc_seqno", "election_id", "elect_close", "min_stake", "total_stake", "finished", "failed"};
    PopulateTableStream stream(txn, "public.elector_applications", columns, 100);
    for (const auto& [mc, s] : states) {
      if (!s->applications_complete || !s->applications) continue;
      const auto& a = *s->applications;
      stream.insert_row(std::make_tuple(mc, a.election_id, a.elect_close, a.min_stake, a.total_stake, a.finished, a.failed));
    }
    stream.finish();
  }
  {
    std::initializer_list<std::string_view> columns = {"mc_seqno", "pubkey", "holder", "adnl", "stake", "max_factor"};
    PopulateTableStream stream(txn, "public.elector_application_participants", columns, 1000);
    for (const auto& [mc, s] : states) {
      if (!s->applications_complete || !s->applications) continue;
      for (const auto& p : s->applications->participants) {
        stream.insert_row(std::make_tuple(mc, p.validator_pubkey, p.stake_holder_address, p.adnl_addr, p.stake, p.max_factor));
      }
    }
    stream.finish();
  }
  {
    std::initializer_list<std::string_view> columns = {"mc_seqno", "gen_utime", "config_hash", "config_boc"};
    PopulateTableStream stream(txn, "public.validator_set_states", columns, 100);
    stream.setConflictDoUpdate({"mc_seqno"}, "");
    for (const auto& task : tasks) {
      if (const auto& s = task.parsed_block_->validator_set_state_) {
        if (s->mc_seqno != task.mc_seqno_) throw std::runtime_error("Validator set MC mismatch");
        stream.insert_row(std::make_tuple(s->mc_seqno, s->gen_utime, s->config_hash, s->config_boc));
      }
    }
    stream.finish();
  }
  {
    std::initializer_list<std::string_view> columns = {
        "account", "mc_seqno", "gen_utime", "code_hash", "data_hash", "kind", "pool", "error"};
    PopulateTableStream stream(txn, "public.stake_holder_states", columns, 100);
    stream.setConflictDoUpdate({"account", "mc_seqno"}, "");
    for (const auto& task : tasks) {
      for (const auto& h : task.parsed_block_->stake_holder_states_) {
        if (h.mc_seqno != task.mc_seqno_) throw std::runtime_error("Holder MC mismatch");
        stream.insert_row(std::make_tuple(h.address, h.mc_seqno, h.gen_utime, h.code_hash, h.data_hash, h.kind, h.pool, h.error));
      }
    }
    stream.finish();
  }
}
