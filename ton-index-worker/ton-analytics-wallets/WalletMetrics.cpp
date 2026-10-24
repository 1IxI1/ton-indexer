#include "WalletMetrics.h"

#include <algorithm>
#include <functional>
#include <limits>
#include <stdexcept>
#include <tuple>
#include <utility>

namespace ton_analytics::wallets {
namespace {
constexpr std::int64_t kDay = 86400;

void require(bool condition, const char* error) {
  if (!condition) throw std::invalid_argument(error);
}

bool valid_id(const BlockId& id) {
  return !id.root_hash.empty() && !id.file_hash.empty();
}

bool seen_active(const WalletObservation& o) {
  return o.orig == AccountStatus::active || o.end == AccountStatus::active;
}

void check_code(const CodeEvidence& e) {
  if (e.kind == EvidenceKind::unknown) {
    require(e.wallet_type_id.empty(), "unknown code cannot have a wallet type");
  } else {
    require(!e.code_hash.empty() && !e.source.empty(), "code evidence requires hash and source");
    require((e.kind == EvidenceKind::qualified) == !e.wallet_type_id.empty(),
            "only qualified code has a wallet type");
  }
}

void check_observation(const WalletObservation& o) {
  require(!o.account.empty() && !o.tx_hash.empty() && valid_id(o.block), "incomplete tx identity");
  require(!o.actual_qualifying_outgoing || !o.outgoing_message_hash.empty(),
          "actual outgoing requires message identity");
  require(o.actual_qualifying_outgoing || o.outgoing_message_hash.empty(),
          "message hash without qualifying outgoing");
  check_code(o.activation_code);
  check_code(o.execution_code);
}

// The full tx identity includes hash, but a second hash for one (account,LT)
// is a contradiction, not a second vote in a distinct-address aggregate.
using TxKey = std::pair<std::string, std::uint64_t>;
void unique_tx(std::map<TxKey, WalletObservation>& by_key, const WalletObservation& o) {
  check_observation(o);
  auto [it, inserted] = by_key.emplace(TxKey{o.account, o.lt}, o);
  require(inserted || it->second == o, "contradictory duplicate (account,LT) transaction");
}

std::map<BlockId, std::int64_t> checked_tips(const std::vector<Tip>& tips,
                                               const std::set<std::int32_t>& workchains) {
  std::map<BlockId, std::int64_t> result;
  std::set<std::int32_t> found;
  std::set<std::tuple<std::int32_t, std::uint64_t, std::uint32_t>> coordinates;
  for (const auto& t : tips) {
    require(valid_id(t.id) && workchains.contains(t.id.workchain), "invalid or unexpected tip");
    require(result.emplace(t.id, t.gen_utime).second, "duplicate shard tip");
    require(coordinates.emplace(t.id.workchain, t.id.shard, t.id.seqno).second,
            "conflicting shard tip at one coordinate");
    found.insert(t.id.workchain);
  }
  require(found == workchains, "not all workchains have tips");
  return result;
}

bool contains(std::int64_t time, std::int64_t from, std::int64_t to) {
  return time >= from && time < to;
}

} // namespace

struct WalletMetrics::State {
  std::optional<BlockId> watermark;
  std::vector<const BlockEnvelope*> chain;
  std::map<std::string, FirstActiveFact> first;
};

WalletMetrics::WalletMetrics(Scope scope, std::size_t max_envelopes,
                             std::size_t max_observations)
    : scope_(std::move(scope)), max_envelopes_(max_envelopes),
      max_observations_(max_observations) {
  require(!scope_.network.empty() && !scope_.zerostate_root_hash.empty() &&
               !scope_.zerostate_file_hash.empty() &&
               !scope_.calc_version.empty() && !scope_.registry_sha256.empty() &&
               !scope_.workchains.empty(), "missing scope/network/zerostate/registry/workchain");
  require(max_envelopes && max_observations, "memory limits must be positive");
}

void WalletMetrics::set_baseline(LifetimeBaseline baseline) {
  require(baseline.scope == scope_, "baseline scope mismatch");
  require(valid_id(baseline.mc) && baseline.mc.workchain == -1 &&
              baseline.canonical_anchor_verified && baseline.full_history_verified &&
              baseline.all_initial_accounts_verified && baseline.shard_frontier_verified &&
              !baseline.attestation_id.empty(), "unverified lifetime baseline");
  require(baseline.kind != BaselineKind::genesis ||
              (baseline.mc.seqno == 0 && baseline.mc_utime >= 0 &&
               baseline.first_active_history.empty() &&
               std::all_of(baseline.shard_tips.begin(), baseline.shard_tips.end(),
                           [&](const Tip& tip) { return tip.gen_utime <= baseline.mc_utime; })),
          "genesis must be MC zero with no future frontier or historical txs");
  checked_tips(baseline.shard_tips, scope_.workchains);
  if (event_checkpoint_ && event_checkpoint_->mc.seqno == baseline.mc.seqno)
    require(event_checkpoint_->mc == baseline.mc &&
                event_checkpoint_->mc_utime == baseline.mc_utime &&
                checked_tips(event_checkpoint_->shard_tips, scope_.workchains) ==
                    checked_tips(baseline.shard_tips, scope_.workchains),
            "conflicting event/lifetime anchors at one MC seqno");
  std::map<TxKey, WalletObservation> previous;
  std::set<std::string> witnessed;
  std::map<std::string, std::uint64_t> historic_lt;
  for (const auto& o : baseline.first_active_history) {
    unique_tx(previous, o);
    require(seen_active(o) && o.now <= baseline.mc_utime &&
                !baseline.genesis_active_accounts.contains(o.account) &&
                witnessed.insert(o.account).second, "invalid historical first-active fact");
    historic_lt.emplace(o.account, o.lt);
  }
  std::size_t observations = baseline.first_active_history.size();
  for (const auto& [seqno, envelope] : envelopes_) {
    require(seqno > baseline.mc.seqno ||
                (event_checkpoint_ && event_checkpoint_->mc.seqno < seqno &&
                 event_checkpoint_->mc.seqno < baseline.mc.seqno),
            "historical pilot blocks cannot overlap certified bootstrap");
    observations += envelope.observations.size();
    for (const auto& o : envelope.observations) {
      unique_tx(previous, o);
      auto first = historic_lt.find(o.account);
      require(first == historic_lt.end() || !seen_active(o) || o.lt > first->second,
              "active tx contradicts certified historical first witness");
    }
  }
  require(observations <= max_observations_ &&
              baseline.genesis_active_accounts.size() <= max_observations_,
          "reference reducer memory limit reached: use durable facts/streaming finalizer");
  if (baseline_ && *baseline_ == baseline) return;
  if (baseline_ && baseline_->attestation_id == baseline.attestation_id)
    throw std::invalid_argument("same attestation has contradictory baseline contents");
  // Explicitly replace a certificate on a new generation, never silently merge facts.
  ++generation_;
  baseline_ = std::move(baseline);
}

void WalletMetrics::set_event_checkpoint(EventRangeCheckpoint checkpoint) {
  require(checkpoint.scope == scope_ && valid_id(checkpoint.mc) && checkpoint.mc.workchain == -1 &&
              checkpoint.mc_utime >= 0 && checkpoint.canonical_anchor_verified &&
              checkpoint.independent_frontier_verified &&
              checkpoint.complete_event_left_boundary_verified &&
              !checkpoint.canonical_anchor_attestation.empty() &&
              !checkpoint.independent_frontier_attestation.empty() &&
              !checkpoint.event_left_boundary_attestation.empty() &&
              checkpoint.canonical_anchor_attestation != checkpoint.independent_frontier_attestation &&
              checkpoint.independent_frontier_attestation != checkpoint.event_left_boundary_attestation &&
              checkpoint.canonical_anchor_attestation != checkpoint.event_left_boundary_attestation,
          "missing independent event-range checkpoint attestations");
  checked_tips(checkpoint.shard_tips, scope_.workchains);
  if (baseline_ && baseline_->mc.seqno == checkpoint.mc.seqno)
    require(baseline_->mc == checkpoint.mc && baseline_->mc_utime == checkpoint.mc_utime &&
                checked_tips(baseline_->shard_tips, scope_.workchains) ==
                    checked_tips(checkpoint.shard_tips, scope_.workchains),
            "conflicting event/lifetime anchors at one MC seqno");
  for (const auto& [seqno, envelope] : envelopes_)
    require(seqno > checkpoint.mc.seqno,
            "event checkpoint cannot launder earlier pilot envelopes");
  if (event_checkpoint_ && *event_checkpoint_ == checkpoint) return;
  if (event_checkpoint_ && event_checkpoint_->event_left_boundary_attestation ==
                               checkpoint.event_left_boundary_attestation)
    throw std::invalid_argument("same event checkpoint proof has contradictory contents");
  ++generation_;
  event_checkpoint_ = std::move(checkpoint);
}

void WalletMetrics::put(BlockEnvelope envelope) {
  require(envelope.scope == scope_ && valid_id(envelope.mc) && valid_id(envelope.prev_mc) &&
              envelope.mc.workchain == -1 && envelope.prev_mc.workchain == -1 &&
              envelope.mc.seqno == envelope.prev_mc.seqno + 1,
          "envelope scope or MC identities invalid");
  checked_tips(envelope.current_shard_tips, scope_.workchains);
  std::map<BlockId, std::int64_t> sources;
  sources.emplace(envelope.mc, envelope.mc_utime);
  for (const auto& b : envelope.new_shard_blocks) {
    require(valid_id(b.id) && scope_.workchains.contains(b.id.workchain) &&
                sources.emplace(b.id, b.gen_utime).second, "duplicate/invalid new block ID");
  }
  std::map<TxKey, WalletObservation> local;
  for (const auto& o : envelope.observations) {
    unique_tx(local, o);
    const auto source = sources.find(o.block);
    require(source != sources.end() && o.now == source->second,
            "tx must belong to a first-included block and have its gen_utime");
  }
  auto old = envelopes_.find(envelope.mc.seqno);
  if (old != envelopes_.end()) {
    if (envelope.revision < old->second.revision) return; // delayed obsolete batch
    if (envelope.revision == old->second.revision) {
      require(envelope == old->second, "same revision has contradictory block contents");
      return;
    }
  }
  std::size_t count = envelope.observations.size();
  for (const auto& [seqno, other] : envelopes_) {
    if (seqno == envelope.mc.seqno) continue;
    count += other.observations.size();
    for (const auto& o : other.observations) unique_tx(local, o);
  }
  if (baseline_) {
    require(envelope.mc.seqno > baseline_->mc.seqno ||
                (event_checkpoint_ && envelope.mc.seqno > event_checkpoint_->mc.seqno &&
                 event_checkpoint_->mc.seqno < baseline_->mc.seqno),
            "replace historical bootstrap certificate to correct pre-anchor facts");
    count += baseline_->first_active_history.size();
    std::map<std::string, std::uint64_t> historic_lt;
    for (const auto& o : baseline_->first_active_history) {
      unique_tx(local, o);
      historic_lt.emplace(o.account, o.lt);
    }
    for (const auto& candidate : envelope.observations) {
      auto first = historic_lt.find(candidate.account);
      require(first == historic_lt.end() || !seen_active(candidate) || candidate.lt > first->second,
              "active tx contradicts certified historical first witness");
    }
  }
  require(count <= max_observations_ &&
              (old != envelopes_.end() || envelopes_.size() < max_envelopes_),
          "reference reducer memory limit reached: use durable facts/streaming finalizer");
  envelopes_[envelope.mc.seqno] = std::move(envelope);
  ++generation_;
}

WalletMetrics::State WalletMetrics::calculate(bool lifetime) const {
  State state;
  const bool use_baseline = lifetime || !event_checkpoint_;
  if (use_baseline ? !baseline_ : !event_checkpoint_) return state;
  const BlockId& anchor_mc = use_baseline ? baseline_->mc : event_checkpoint_->mc;
  const std::int64_t anchor_time = use_baseline ? baseline_->mc_utime : event_checkpoint_->mc_utime;
  const auto& anchor_tips = use_baseline ? baseline_->shard_tips : event_checkpoint_->shard_tips;
  if (lifetime) {
    for (const auto& account : baseline_->genesis_active_accounts) {
      require(!account.empty(), "empty genesis address");
      FirstActiveFact fact;
      fact.genesis_state = true;
      fact.witness.account = account;
      state.first.emplace(account, std::move(fact));
    }
    for (const auto& o : baseline_->first_active_history)
      state.first.emplace(o.account, FirstActiveFact{false, o});
  }

  auto frontier = checked_tips(anchor_tips, scope_.workchains);
  std::set<BlockId> seen_ids;
  std::map<std::tuple<std::int32_t, std::uint64_t, std::uint32_t>, BlockId> coordinates;
  for (const auto& [id, time] : frontier) {
    seen_ids.insert(id);
    coordinates.emplace(std::make_tuple(id.workchain, id.shard, id.seqno), id);
  }
  BlockId last = anchor_mc;
  std::int64_t mc_time = anchor_time;
  for (auto it = envelopes_.upper_bound(last.seqno); it != envelopes_.end(); ++it) {
    const auto& e = it->second;
    if (e.mc.seqno != last.seqno + 1 || e.prev_mc != last ||
        e.mc_utime < mc_time || !e.graph_diff_verified || !e.time_rules_verified ||
        e.graph_diff_attestation.empty() || e.time_rules_attestation.empty() ||
        e.tx_inventory_attestation.empty()) break;
    if ((use_baseline && event_checkpoint_ && e.mc.seqno == event_checkpoint_->mc.seqno &&
         (e.mc != event_checkpoint_->mc || e.mc_utime != event_checkpoint_->mc_utime ||
          checked_tips(e.current_shard_tips, scope_.workchains) !=
              checked_tips(event_checkpoint_->shard_tips, scope_.workchains))) ||
        (!use_baseline && baseline_ && e.mc.seqno == baseline_->mc.seqno &&
         (e.mc != baseline_->mc || e.mc_utime != baseline_->mc_utime ||
          checked_tips(e.current_shard_tips, scope_.workchains) !=
              checked_tips(baseline_->shard_tips, scope_.workchains)))) break;
    std::map<BlockId, const CoveredBlock*> blocks;
    std::set<std::tuple<std::int32_t, std::uint64_t, std::uint32_t>> batch_coordinates;
    bool graph_ok = true;
    for (const auto& b : e.new_shard_blocks) {
      const auto coordinate = std::make_tuple(b.id.workchain, b.id.shard, b.id.seqno);
      auto previous = coordinates.find(coordinate);
      if (!valid_id(b.id) || seen_ids.contains(b.id) ||
          (previous != coordinates.end() && previous->second != b.id) ||
          !batch_coordinates.insert(coordinate).second ||
          !blocks.emplace(b.id, &b).second) { graph_ok = false; break; }
    }
    if (!graph_ok) break;
    // Scanner completion order is irrelevant: resolve parents recursively and
    // reject cycles, missing ancestors, duplicate coordinates and orphan tips.
    std::map<BlockId, int> visits;
    std::vector<const CoveredBlock*> ordered;
    std::function<bool(const BlockId&)> visit = [&](const BlockId& id) {
      auto found = blocks.find(id);
      if (found == blocks.end()) return frontier.contains(id);
      int& mark = visits[id];
      if (mark == 1) return false;
      if (mark == 2) return true;
      mark = 1;
      const auto& b = *found->second;
      if (!b.transactions_complete || b.predecessors.empty() || b.predecessors.size() > 2)
        return false;
      std::set<BlockId> parents;
      for (const auto& parent : b.predecessors) {
        if (!parents.insert(parent).second || parent.workchain != b.id.workchain ||
            parent.seqno >= b.id.seqno || !visit(parent)) return false;
        const auto in_batch = blocks.find(parent);
        const auto time = in_batch == blocks.end() ? frontier.at(parent) : in_batch->second->gen_utime;
        if (b.gen_utime < time) return false;
      }
      mark = 2;
      ordered.push_back(&b);
      return true;
    };
    for (const auto& [id, b] : blocks)
      if (!visit(id)) { graph_ok = false; break; }
    if (!graph_ok) break;
    auto next_frontier = frontier;
    std::map<BlockId, std::int64_t> reachable = frontier;
    std::map<BlockId, unsigned> children;
    for (const auto* source : ordered) {
      const auto& b = *source;
      for (const auto& parent : b.predecessors) {
        auto found = reachable.find(parent);
        if (found == reachable.end() || ++children[parent] > 2) { graph_ok = false; break; }
        next_frontier.erase(parent);
      }
      if (!graph_ok) break;
      reachable.emplace(b.id, b.gen_utime);
      next_frontier.emplace(b.id, b.gen_utime);
    }
    if (!graph_ok || next_frontier != checked_tips(e.current_shard_tips, scope_.workchains) ||
        !e.mc_transactions_complete) break;
    frontier = std::move(next_frontier);
    for (const auto* source : ordered) {
      seen_ids.insert(source->id);
      coordinates.emplace(std::make_tuple(source->id.workchain, source->id.shard,
                                          source->id.seqno), source->id);
    }
    state.chain.push_back(&e);
    if (lifetime) {
      for (const auto& o : e.observations) {
        if (!seen_active(o)) continue;
        auto [first, inserted] = state.first.emplace(o.account, FirstActiveFact{false, o});
        if (!inserted && !first->second.genesis_state &&
            std::tie(o.lt, o.tx_hash) <
                std::tie(first->second.witness.lt, first->second.witness.tx_hash)) {
          first->second.witness = o;
        }
      }
    }
    state.watermark = e.mc;
    last = e.mc;
    mc_time = e.mc_utime;
  }
  return state;
}

std::optional<BlockId> WalletMetrics::contiguous_watermark() const {
  return calculate(static_cast<bool>(baseline_)).watermark;
}

std::optional<BlockId> WalletMetrics::event_watermark() const {
  return calculate(false).watermark;
}

std::optional<FirstActiveFact> WalletMetrics::first_active(const std::string& account) const {
  auto state = calculate(true);
  auto found = state.first.find(account);
  if (found == state.first.end()) return std::nullopt;
  if (found->second.genesis_state ||
      (baseline_ && std::any_of(baseline_->first_active_history.begin(),
                                baseline_->first_active_history.end(),
                                [&](const WalletObservation& o) { return o.account == account; })))
    return found->second; // prior certified history is not invalidated by later unknowns
  // An unresolved earlier status might hide the actual first active event.
  for (const auto* e : state.chain) {
    if (!e->mc_activation_inputs_complete) return std::nullopt;
    for (const auto& b : e->new_shard_blocks)
      if (!b.activation_inputs_complete) return std::nullopt;
    if (e->mc == found->second.witness.block ||
        std::any_of(e->new_shard_blocks.begin(), e->new_shard_blocks.end(),
                    [&](const CoveredBlock& b) { return b.id == found->second.witness.block; })) break;
  }
  return found->second;
}

DayMetrics WalletMetrics::day(std::int64_t start) const {
  DayMetrics out;
  out.utc_day_start = start;
  out.generation = generation_;
  require(start >= 0 && start % kDay == 0 &&
              start <= std::numeric_limits<std::int64_t>::max() - kDay,
          "UTC day must be aligned and within range");
  const auto end = start + kDay;
  const auto lifetime = calculate(true);
  const auto activity = calculate(false);

  // Event-range checkpoint and lifetime baseline are separate certificates.
  // Only genesis proves the partial network day before its zerostate is empty.
  auto has_left_boundary = [&](bool use_baseline, std::int64_t from) {
    if (from < 0) return false;
    if (use_baseline && !baseline_) return false;
    if (!use_baseline && !event_checkpoint_) return false;
    const auto anchor_time = use_baseline ? baseline_->mc_utime : event_checkpoint_->mc_utime;
    if (use_baseline && baseline_->kind == BaselineKind::genesis) {
      return anchor_time >= 0 &&
             (from > anchor_time || (from <= anchor_time && anchor_time < from + kDay));
    }
    if (anchor_time >= from) return false;
    const auto& tips = use_baseline ? baseline_->shard_tips : event_checkpoint_->shard_tips;
    return std::all_of(tips.begin(), tips.end(),
                       [&](const Tip& t) { return t.gen_utime < from; });
  };
  auto covered = [&](const State& state, std::int64_t from, std::int64_t to,
                     bool activation, bool use_baseline,
                     std::set<std::string>* active_addresses) {
    if (!has_left_boundary(use_baseline, from)) return false;
    bool closed = false;
    bool complete = true;
    for (const auto* e : state.chain) {
      if (contains(e->mc_utime, from, to)) {
        complete &= activation ? e->mc_activation_inputs_complete : e->mc_activity_inputs_complete;
      }
      for (const auto& b : e->new_shard_blocks) {
        if (contains(b.gen_utime, from, to)) {
          complete &= activation ? b.activation_inputs_complete : b.activity_inputs_complete;
        }
      }
      for (const auto& o : e->observations) {
        if (!contains(o.now, from, to)) continue;
        if (activation && seen_active(o) && o.orig == AccountStatus::uninit &&
            o.end == AccountStatus::active && o.activation_code.kind == EvidenceKind::unknown) {
          // Unknown candidate may or may not be a wallet; do not make it zero.
          auto first = state.first.find(o.account);
          if (first != state.first.end() && !first->second.genesis_state &&
              first->second.witness == o) complete = false;
        }
        if (!activation && o.actual_qualifying_outgoing) {
          if (o.execution_code.kind == EvidenceKind::unknown) complete = false;
          if (active_addresses && o.execution_code.kind == EvidenceKind::qualified)
            active_addresses->insert(o.account);
        }
      }
      if (e->mc_utime >= to && std::all_of(e->current_shard_tips.begin(),
                                           e->current_shard_tips.end(),
                                           [&](const Tip& t) { return t.gen_utime >= to; })) {
        closed = true;
        break;
      }
    }
    return closed && complete;
  };

  // Lifetime needs complete status/code resolution from baseline to the right
  // frontier, independently of whether the current day's DAU is ready.
  bool lifetime_ready = covered(lifetime, start, end, true, true, nullptr);
  if (lifetime_ready) {
    for (const auto* e : lifetime.chain) {
      if (e->mc_utime < end) lifetime_ready &= e->mc_activation_inputs_complete;
      for (const auto& b : e->new_shard_blocks)
        if (b.gen_utime < end) lifetime_ready &= b.activation_inputs_complete;
      if (e->mc_utime >= end && std::all_of(e->current_shard_tips.begin(),
                                            e->current_shard_tips.end(),
                                            [&](const Tip& t) { return t.gen_utime >= end; })) break;
    }
    for (const auto& [account, fact] : lifetime.first) {
      const auto& o = fact.witness;
      if (!fact.genesis_state && o.now < end && o.orig == AccountStatus::uninit &&
          o.end == AccountStatus::active && o.activation_code.kind == EvidenceKind::unknown)
        lifetime_ready = false;
    }
  }
  if (lifetime_ready) {
    std::uint64_t daily = 0, total = 0;
    for (const auto& [account, fact] : lifetime.first) {
      const auto& o = fact.witness;
      if (fact.genesis_state || o.now >= end || o.orig != AccountStatus::uninit ||
          o.end != AccountStatus::active || o.activation_code.kind != EvidenceKind::qualified) continue;
      ++total;
      if (o.now >= start) {
        ++daily;
        ++out.activation_types[o.activation_code.wallet_type_id];
      }
    }
    out.daily_activations = daily;
    out.cumulative_activations = total;
  }
  auto addresses = [&](bool use_baseline, bool rolling)
      -> std::optional<std::set<std::string>> {
    if (use_baseline ? !baseline_ : !event_checkpoint_) return std::nullopt;
    std::int64_t from = start;
    if (rolling) {
      from = start >= 29 * kDay ? start - 29 * kDay : -1;
      if (use_baseline && baseline_->kind == BaselineKind::genesis &&
          baseline_->mc_utime >= 0) {
        const auto genesis_day = baseline_->mc_utime / kDay * kDay;
        from = std::max(from, genesis_day);
      }
    }
    if (from < 0 || from > start) return std::nullopt;
    std::set<std::string> result;
    if (!covered(use_baseline ? lifetime : activity, from, end, false, use_baseline, &result))
      return std::nullopt;
    return result;
  };
  auto metric = [&](bool rolling) -> std::optional<std::uint64_t> {
    auto from_lifetime_anchor = addresses(true, rolling);
    auto from_event_anchor = addresses(false, rolling);
    if (from_lifetime_anchor && from_event_anchor &&
        *from_lifetime_anchor != *from_event_anchor)
      throw std::invalid_argument("event and lifetime anchors disagree on activity addresses");
    if (from_lifetime_anchor) return from_lifetime_anchor->size();
    if (from_event_anchor) return from_event_anchor->size();
    return std::nullopt;
  };
  out.dau = metric(false);
  out.mau_30d = metric(true);
  return out;
}

} // namespace ton_analytics::wallets
