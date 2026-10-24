// Opt-in bounded secondary diagnostic. Launch only after the chief's pilot
// slot is claimed; the compile-time switch defaults OFF. Never dbs_readonly.
#include "Options.h"
#include "ValidatorFacts.h"  // separately owned renderer: render_batch_json(stage::Output)
#include "ValidatorCoreBridge.h"  // separately owned verified-MC adapter
#include "DbScanner.h"

#include "td/actor/coro_utils.h"
#include "td/utils/crypto.h"
#include "td/utils/logging.h"
#include "td/utils/misc.h"

#include <csignal>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string_view>
#include <sys/resource.h>
#include <unistd.h>

namespace {
using tonstat::validators::Options;

void require(bool condition, const char *reason) {
  if (!condition) throw std::runtime_error(reason);
}

void timeout(int) {
  // Signal-safe diagnostic; never serialize a partial result on timeout.
  constexpr char message[] =
      "{\"dataset\":\"validators\",\"status\":\"pending\",\"reason\":\"io_wall_timeout\",\"writer_committed\":false}\n";
  (void)write(STDERR_FILENO, message, sizeof(message) - 1);
  _exit(1);
}

void enforce_budget(const Options &o) {
  auto limit = [](int resource, rlim_t cap) {
    struct rlimit existing {};
    require(getrlimit(resource, &existing) == 0 && existing.rlim_max >= cap,
            "budget exceeds process resource hard limit");
    struct rlimit requested { cap, cap };
    require(setrlimit(resource, &requested) == 0, "cannot enforce resource limit");
  };
  limit(RLIMIT_NOFILE, o.nofile_budget);
  limit(RLIMIT_CPU, o.cpu_seconds);
  limit(RLIMIT_AS, static_cast<rlim_t>(o.memory_mib) * 1024u * 1024u);
  require(std::signal(SIGALRM, timeout) != SIG_ERR, "cannot install wall-timeout handler");
  alarm(o.wall_seconds);  // total wall time incl. blocked I/O/catch-up; no backfill loop
}

ton::BlockIdExt full_mc(uint32_t seqno, const std::string &root, const std::string &file) {
  td::Bits256 root_hash, file_hash;
  require(root_hash.from_hex(td::Slice(root)) == 256 &&
          file_hash.from_hex(td::Slice(file)) == 256, "invalid full MC hash");
  return {ton::masterchainId, ton::shardIdAll, seqno, root_hash, file_hash};
}

// DbScanner::request_catch_up puts its promise BEFORE the mode. Bridge it to
// the promise-last actor ask API and propagate errors rather than CHECK them.
class CatchUp final : public td::actor::Actor {
 public:
  explicit CatchUp(td::actor::ActorId<DbScanner> scanner) : scanner_(scanner) {}
  void once(td::Promise<td::Unit> promise) {
    td::actor::send_closure(scanner_, &DbScanner::request_catch_up, std::move(promise),
                            ton::validator::CatchUpMode::Force);
  }
 private:
  td::actor::ActorId<DbScanner> scanner_;
};

bool has_ready_metric(const analytics::validators::stage::Output &out) {
  using analytics::validators::stage::Status;
  for (const auto *m : {&out.count, &out.selected_initial, &out.accepted,
                         &out.frozen_remaining, &out.settlement, &out.apr, &out.apy}) {
    if (m->status == Status::ready) return true;
  }
  return false;
}

const char *core_status_name(tonstat::core::Status status) {
  switch (status) {
    case tonstat::core::Status::verified_local_archive: return "verified_local_archive";
    case tonstat::core::Status::incomplete: return "incomplete";
    case tonstat::core::Status::error: return "error";
  }
  return "unknown";
}

// Escape at most the first `limit` source bytes, including invalid UTF-8 and
// controls, so archive-derived issue text remains one bounded JSON string.
std::string diagnostic_string(std::string_view text, size_t limit) {
  static constexpr char hex[] = "0123456789abcdef";
  std::string escaped = "\"";
  for (size_t i = 0; i < text.size() && i < limit; ++i) {
    const unsigned char c = static_cast<unsigned char>(text[i]);
    if (c == '"' || c == '\\') {
      escaped += '\\';
      escaped += static_cast<char>(c);
    } else if (c < 0x20 || c >= 0x7f) {
      escaped += "\\u00";
      escaped += hex[c >> 4];
      escaped += hex[c & 15];
    } else {
      escaped += static_cast<char>(c);
    }
  }
  escaped += '"';
  return escaped;
}

// Diagnostics go to stderr only. The caller returns an error, discarding any
// previously staged rows; never render an unauthenticated numeric result.
void bridge_failure(const char *reason, const tonstat::core::AnchorEvidence *core) {
  std::cerr << "{\"dataset\":\"validators\",\"status\":\"pending\",\"reason\":\""
            << reason << "\",\"core_status\":\""
            << (core ? core_status_name(core->status) : "missing") << '"';
  if (core && !core->issues.empty()) {
    std::cerr << ",\"core_issue_code\":" << diagnostic_string(core->issues.front().code, 80)
              << ",\"core_issue_detail\":" << diagnostic_string(core->issues.front().detail, 160);
  }
  std::cerr << ",\"writer_committed\":false}\n";
  throw std::runtime_error(reason);
}

td::actor::Task<td::Unit> run(td::actor::ActorId<DbScanner> scanner,
                              td::actor::ActorId<CatchUp> gate, Options o) {
  auto sync = co_await td::actor::ask(gate, &CatchUp::once).wrap();
  if (sync.is_error()) co_return sync.move_as_error();

  // The explicit CLI full MC0 pin is checked by core against trusted MC0
  // root/file and the decoded MC post-state config/global ID. No archived MC0
  // handle is required; this does not prove MC0 archive presence or
  // zerostate-to-anchor chain continuity.
  tonstat::core::NetworkPin pin{full_mc(0, o.zerostate_root, o.zerostate_file)};
  std::vector<td::Bits256> allowed_codes;
  if (!o.elector_code_hash.empty()) {
    td::Bits256 code_hash;
    require(code_hash.from_hex(td::Slice(o.elector_code_hash)) == 256,
            "invalid elector code hash");
    // Operator opt-in is only the caller allowlist: the decoder separately
    // requires its compiled, hard-reviewed elector code hash to match.
    allowed_codes.push_back(code_hash);
  }
  // Read only the selected MC block and post-state. fetch_seqno would run
  // IndexQuery over shard tips and ancestors, which this auxiliary MC-only
  // verifier neither needs nor claims to have verified.
  std::vector<std::string> rows;
  for (const auto &anchor : o.anchors) {
    const auto expected = full_mc(anchor.seqno, anchor.root_hash, anchor.file_hash);
    auto lookup = co_await td::actor::ask(scanner, &DbScanner::get_mc_block_handle, anchor.seqno).wrap();
    if (lookup.is_error()) co_return lookup.move_as_error();
    const auto handle = lookup.move_as_ok();
    if (!handle || handle->id() != expected) {
      co_return td::Status::Error("scanner MC handle differs from external full candidate ID");
    }
    auto read = co_await td::actor::ask(scanner, &DbScanner::fetch_block_by_id, expected).wrap();
    if (read.is_error()) co_return read.move_as_error();
    try {
      // This is a one-entry MC-only adapter, not an IndexQuery snapshot.
      // Its refs remain alive through the bridge's synchronous verification.
      schema::MasterchainBlockDataState loaded;
      loaded.shard_blocks_.push_back(read.move_as_ok());
      require(loaded.shard_blocks_.size() == 1, "missing MC block/state");
      const auto &mc = loaded.shard_blocks_.front();
      require(static_cast<bool>(mc.handle) && mc.block_data.not_null() && mc.block_state.not_null(),
              "missing MC handle/block/state");
      const auto id = mc.handle->id();
      require(id == expected && mc.block_data->block_id() == expected,
              "scanner MC full root/file ID differs from external candidate");
      require(mc.block_data->root_cell().not_null(), "missing raw MC block root");
      const auto boc = mc.block_data->data();
      require(!boc.empty(), "missing raw MC block BoC");
      const auto observed_file_hash = td::hex_encode(td::sha256(boc.as_slice()));
      auto state_root = mc.block_state->get_hash().as_bits256();
      require(state_root != td::Bits256{}, "missing MC post-state root");

       // The separately owned bridge alone creates stage anchor evidence from
       // native raw checks; no boolean based on hash equality is set here.
       const auto result = tonstat::validators::run_verified_mc(loaded, expected, pin, allowed_codes);
       if (!result.core) bridge_failure("bridge_missing_core", nullptr);
       const auto *core = result.core.get();
       if (core->status != tonstat::core::Status::verified_local_archive &&
           has_ready_metric(result.stage))
         bridge_failure("ready_without_core_verification", core);
       if (core->status == tonstat::core::Status::error) bridge_failure("native_core_error", core);
       if (core->status == tonstat::core::Status::incomplete) bridge_failure("native_core_incomplete", core);
       if (core->status != tonstat::core::Status::verified_local_archive)
         bridge_failure("native_core_unknown_status", core);
       if (core->mc.id != expected || result.stage.mc_id != expected)
         bridge_failure("bridge_full_mc_id_mismatch", core);
       if (core->mc.state_root != state_root ||
           result.stage.post_state_root != state_root)
         bridge_failure("bridge_post_state_root_mismatch", core);
       if (!result.stage.producer_only || result.stage.writer_committed ||
           result.stage.publication)
         bridge_failure("bridge_producer_flags_mismatch", core);
       if (core->network != o.network) bridge_failure("bridge_network_mismatch", core);
       rows.push_back(tonstat::validators::render_batch_json(result.stage));
       require(!rows.back().empty(), "empty pending renderer result");
       // This is a raw scanner observation, not a publication or a proof by
       // hash equality. The renderer serializes bridge-assigned stage status.
       rows.push_back(std::string("{\"dataset\":\"validators\",\"status\":\"pending\","
                                  "\"reason\":\"producer_diagnostic\",\"core_status\":\"") +
                      core_status_name(core->status) +
                     "\",\"mc_id\":\"" + id.to_str() +
                     "\",\"post_state_root\":\"" + state_root.to_hex() +
                     "\",\"observed_block_root\":\"" + mc.block_data->root_cell()->get_hash().as_bits256().to_hex() +
                     "\",\"observed_boc_sha256\":\"" + observed_file_hash +
                      "\",\"read_scope\":\"mc_only_not_full_snapshot\",\"loaded_blocks\":1" +
                      ",\"writer_committed\":false}");
    } catch (const std::exception &e) {
      co_return td::Status::Error(td::Slice(e.what()));
    }
  }
  // All-or-nothing output; any missing state or catch-up error discards rows.
  for (const auto &row : rows) std::cout << row << '\n';
  co_return td::Unit();
}
}  // namespace

int main(int argc, char **argv) {
  Options o;
  try {
    o = tonstat::validators::parse_options({argv + 1, argv + argc});
    // A bare -DNAME=0 must NOT bypass the default-off safety gate.
#if !defined(TON_VALIDATORS_SECONDARY_SAFETY_REVIEWED) || TON_VALIDATORS_SECONDARY_SAFETY_REVIEWED != 1
    throw std::runtime_error("STOP: secondary NodeDB integration requires independent safety review");
#endif
    enforce_budget(o);
    // Recheck canonical disjoint paths immediately before the secondary actor.
    // Host-side races require operational isolation and a single-process slot.
    tonstat::validators::preflight_paths(o);
  } catch (const std::exception &e) {
    std::cerr << "{\"dataset\":\"validators\",\"status\":\"pending\","
                 "\"reason\":\"preflight_or_safety_gate_failed\",\"writer_committed\":false}\n";
    std::cerr << "validators preflight: " << e.what() << '\n';
    return 2;
  }
  SET_VERBOSITY_LEVEL(verbosity_WARNING);
  td::actor::Scheduler scheduler({2});
  td::actor::ActorOwn<DbScanner> scanner;
  td::actor::ActorOwn<CatchUp> gate;
  auto code = std::make_shared<int>(1);  // pending even after a successful read
  auto watcher = td::create_shared_destructor([] { td::actor::SchedulerContext::get().stop(); });
  scheduler.run_in_context([&, watcher = std::move(watcher)]() mutable {
    // Only dbs_secondary; false avoids the scanner's implicit catch-up on head
    // queries. 3600s prevents periodic catch-up during the <=300s wall budget.
    scanner = td::actor::create_actor<DbScanner>("secondary-validators", o.db_root.string(),
                                                dbs_secondary, o.secondary_work_dir.string(),
                                                3600.0f, false);
    gate = td::actor::create_actor<CatchUp>("validators-catchup", scanner.get());
    auto done = td::PromiseCreator::lambda([watcher = std::move(watcher), code](td::Result<td::Unit> r) {
      if (r.is_error()) {
        std::cerr << "{\"dataset\":\"validators\",\"status\":\"pending\","
                     "\"reason\":\"secondary_read_or_stage_failed\",\"writer_committed\":false}\n";
        std::cerr << "validators diagnostic: " << r.move_as_error().to_string() << '\n';
      }
      *code = 1;  // producer-only pending is deliberately nonzero
    });
    td::connect(std::move(done), run(scanner.get(), gate.get(), o).start());
  });
  scheduler.run();
  return *code;
}
