#pragma once

// IndexData.h uses base64_encode without including its own declaration.
// clang-format off
#include "td/utils/base64.h"
#include "IndexData.h"
// clang-format on

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace analytics::validators {

// No writer, DB access, network calls or transaction-diff account lookup.
// Version covers the strictly decoded Elector data layout in elector-code.fc.
inline constexpr const char *kDecoderVersion =
    "validator-post-state-v1/elector-fc-2026-10";
// The ONLY Elector code hash reviewed for the frozen-dictionary layout above.
// Other hashes, including older D64 variants, must remain pending until their
// exact historical code and layout are independently reviewed.
inline constexpr std::string_view kReviewedElectorCodeHash =
    "6217F872C99FAFCB870F2C11A362F59339BE95095F70D00B9CFF2F6DCD69D3DD";

enum class Readiness { ready, pending, invalid };

struct Metric {
  Readiness status{Readiness::pending};
  std::string reason{"not_evaluated"};
  // Decimal nanoTON for stake; decimal integer for count. Null unless ready.
  std::optional<std::string> value;
};

struct Member {
  uint16_t index{}; // Original Hashmap 16 key, not iterator position.
  td::Bits256 pubkey;
  uint64_t weight{};
  std::optional<td::Bits256> adnl; // Legacy validator descriptor has no ADNL.
};

struct FrozenMember {
  td::Bits256 pubkey;
  td::Bits256 raw_holder; // Raw uint256: not an inferred workchain address.
  uint64_t weight{};
  std::string stake_nanoton;
  bool banned{};
};

struct Snapshot {
  std::string decoder_version{kDecoderVersion};
  std::string network_zerostate;
  ton::BlockIdExt mc_id;
  td::Bits256 state_hash;
  bool state_update_verified{};
  uint32_t gen_utime{};
  Metric count;
  Metric frozen_remaining;
  std::optional<td::Bits256> config34_hash, config32_hash, config35_hash,
      config36_hash;
  uint32_t utime_since{}, utime_until{};
  uint16_t total{}, main{};
  uint64_t total_weight{};
  std::vector<Member> members;
  std::optional<td::Bits256> elector_address, elector_account_hash,
      elector_code_hash, elector_data_hash;
  std::optional<td::Bits256> past_elections_root_hash, frozen_root_hash;
  std::optional<uint32_t> election_id, unfreeze_at, stake_held_for;
  std::optional<td::Bits256> matched_vset_hash;
  std::optional<std::string> frozen_declared_total_nanoton;
  std::vector<FrozenMember> frozen;
};

struct Input {
  // All three identifiers MUST be supplied by the reader of this exact
  // post-state.
  std::string network_zerostate;
  ton::BlockIdExt expected_mc_id;
  td::Bits256 expected_state_hash;
  // Must be independently established by the caller (block state_update /
  // trusted node reader); comparing the supplied hashes alone is not a Merkle
  // proof.
  bool state_update_verified{false};
  // Additional caller opt-in only: a hash must ALSO be pinned as reviewed in
  // this module. This list can never extend the decoder's trusted code hashes.
  // Empty leaves stake pending, even for the pinned code.
  std::vector<td::Bits256> supported_elector_code_hashes;
};

// Fail-closed policy predicates, exposed for deterministic local tests.
// Zerostate identity is exactly a nonzero 256-bit hex root hash (64 digits),
// not an arbitrary network name or an unverified full zerostate ID.
bool valid_network_zerostate(std::string_view hash_hex);
bool elector_code_enabled_for_decoder(
    const td::Bits256 &code_hash,
    const std::vector<td::Bits256> &caller_allowlist);

// Narrow synchronous cell seam: production calls these after reading the
// corresponding config/account from the SAME verified MC state. Exposed so a
// local TL-B fixture can exercise the actual decoder, not a copy of it.
// Passing arbitrary cells to these functions is NOT an MC/root proof.
void decode_validator_set_cell(Snapshot &snapshot,
                               const td::Ref<vm::Cell> &config34);
void decode_elector_data_cell(Snapshot &snapshot,
                              const td::Ref<vm::Cell> &elector_data,
                              const td::Bits256 &elector_code_hash,
                              const std::vector<td::Bits256> &caller_allowlist);

// Synchronous: state, its cells and reader must remain alive for the entire
// call. Never substitutes account_states_ (a per-transaction diff) for MC
// ShardAccounts. Count and frozen stake have independent readiness; missing
// frozen means pending, not zero. On a failed invariant, no partial metric
// value or partial members escape.
td::Result<Snapshot>
extract_validator_snapshot(const schema::MasterchainBlockDataState &loaded,
                           const Input &input);

// Pure invariant checks also used by the deterministic, synthetic tests. They
// invalidate only the affected metric and clear its incomplete rows.
void validate_roster(Snapshot &snapshot);
void validate_frozen(Snapshot &snapshot,
                     const std::string &declared_total_nanoton);

} // namespace analytics::validators
