#include "../../src/assets_analytics/DnsAuctionEvents.h"

#include <cassert>
#include <limits>
#include <string>
#include <vector>

using namespace assets_analytics::dns;

namespace {
std::string h(char c) { return std::string(64, c); }
std::string b(char c) { return std::string(43, c) + "="; }
std::string a(char c) { return "0:" + h(c); }

Request request() {
  Request r;
  r.network = "testnet";
  r.zerostate = "zerostate:root:file";
  r.mc_block = {-1, std::numeric_limits<int64_t>::min(), 11, b('A'), b('B')};
  r.registry_digest = h('c');
  r.item_addresses = {a('a'), a('b')};
  r.limits = {2, 8, 32, 5, 60, 60, 200000};
  return r;
}

Tx tx(char item, char hash, uint64_t lt) {
  Tx t;
  t.block = {0, std::numeric_limits<int64_t>::min(), 21, b('D'), b('E')};
  t.item_address = a(item);
  t.hash = h(hash);
  t.lt = lt;
  t.now = 1000 + static_cast<uint32_t>(lt);
  t.mc_seqno = 11;
  t.state_hash_before = h('1');
  t.state_hash_after = h('2');
  t.was_active = true;
  t.is_active = true;
  t.incoming = Message{h('e'), a('f'), t.item_address, 0, "1200000000", false};
  return t;
}

bool has(const Batch& batch, Signal signal, const std::string& item = "") {
  for (const auto& candidate : batch.candidates)
    if (candidate.signal == signal && (item.empty() || candidate.tx.item_address == item)) return true;
  return false;
}
}  // namespace

int main() {
  static_assert(!Batch::first_sale_complete && !Batch::volume_complete);
  auto r = request();
  Tx first = tx('a', '3', 1);
  first.was_active = false;
  Tx outbid = tx('a', '4', 2);
  outbid.outgoing.push_back({h('5'), a('a'), a('f'), 0x557cea20U, "900000000", false});
  Tx reauction = tx('a', '6', 3);
  reauction.incoming->opcode = 0x4ed14b65U;
  Tx second_name = tx('b', '7', 4);
  second_name.was_active = false;
  const std::vector<BlockId> included{r.mc_block, first.block};
  assert(same_ordered_diff(included, included, r.mc_block));
  // A repeated current tip replacing a diff block is not first-included,
  // even if its own full ID and transactions are internally consistent.
  BlockId repeated_tip = first.block;
  repeated_tip.seqno++;
  repeated_tip.root_hash = b('F');
  assert(!same_ordered_diff({r.mc_block, repeated_tip}, included, r.mc_block));
  assert(!same_ordered_diff(included, {r.mc_block, repeated_tip}, r.mc_block));
  assert(!same_ordered_diff({first.block, r.mc_block}, included, r.mc_block));
  assert(!same_ordered_diff(included, {first.block, r.mc_block}, r.mc_block));
  assert(!same_ordered_diff(included, {r.mc_block}, r.mc_block));
  assert(!same_ordered_diff(included, {r.mc_block, first.block, first.block}, r.mc_block));
  assert(!same_ordered_diff({r.mc_block, first.block, first.block},
                            {r.mc_block, first.block, first.block}, r.mc_block));
  assert(!same_ordered_diff({r.mc_block, r.mc_block}, {r.mc_block, r.mc_block}, r.mc_block));
  assert(tx_within_source_block(100, 1000, 100, 101, 1000));
  assert(!tx_within_source_block(99, 1000, 100, 101, 1000));
  assert(!tx_within_source_block(101, 1000, 100, 101, 1000));
  assert(!tx_within_source_block(100, 1001, 100, 101, 1000));
  assert(!tx_within_source_block(100, 1000, 101, 101, 1000));
  assert(!tx_within_source_block(100, 1000, 100, 101, -1));
  Batch two_auctions = extract_from_first_included({first, outbid, reauction, second_name}, r, included);
  assert(two_auctions.valid && two_auctions.candidates.size() == 7);
  assert(has(two_auctions, Signal::first_auction_candidate, a('a')));
  assert(has(two_auctions, Signal::first_auction_candidate, a('b')));
  assert(has(two_auctions, Signal::release_reauction_candidate, a('a')));
  assert(has(two_auctions, Signal::refund_candidate, a('a')));
  // Two domains and many bids are NOT two first sales, nor a sum of bid values.
  for (const auto& c : two_auctions.candidates) {
    assert(!c.reason.empty() && c.mc_block.file_hash == b('B'));
    assert(c.tx.block.root_hash == b('D') && c.tx.block.file_hash == b('E'));
    assert(c.tx.state_hash_before == h('1') && c.tx.state_hash_after == h('2'));
    assert(c.tx.incoming && c.tx.incoming->value_nanoton);
  }

  Tx settlement = tx('a', '8', 5);
  settlement.incoming->opcode = 0x1a0b9d51U; // edit_content can trigger settlement
  settlement.outgoing.push_back({h('9'), a('a'), a('d'), 0x370fec51U, "100", false});
  auto settled = extract_from_first_included({outbid, settlement}, r, included);
  assert(settled.valid && has(settled, Signal::settlement_candidate));
  assert(!has(extract_from_first_included({outbid}, r, included), Signal::settlement_candidate));
  assert(!has(extract_from_first_included({settlement}, r, included), Signal::bid_candidate));
  // Outgoing payout attempt is not winning bid (nor proof of collection receipt).
  assert(settled.candidates.back().tx.outgoing[0].value_nanoton == "100");

  Tx expired = tx('a', 'a', 6);
  expired.incoming->opcode = 0x2fcb26a2U;
  expired.auction_end_before_hint = 10;
  expired.auction_hint_state_hash = expired.state_hash_before;
  auto expiry = extract_from_first_included({expired}, r, included);
  assert(expiry.valid && has(expiry, Signal::expiry_candidate));
  assert(!has(expiry, Signal::settlement_candidate));
  expired.auction_hint_state_hash = h('f');
  assert(!extract_from_first_included({expired}, r, included).valid);

  Tx transfer = tx('a', 'b', 7);
  transfer.incoming->opcode = 0x5fcc3d14U;
  auto possible_secondary = extract_from_first_included({transfer}, r, included);
  assert(possible_secondary.valid && has(possible_secondary, Signal::secondary_transfer_candidate));
  assert(!has(possible_secondary, Signal::settlement_candidate));
  Tx unknown_code = tx('b', 'c', 8);
  unknown_code.incoming->opcode = 0xbadf00dU;
  auto unknown = extract_from_first_included({unknown_code}, r, included);
  assert(unknown.valid && has(unknown, Signal::other_item_transaction));
  // Even a recognized opcode on an unverified item code cannot promote a sale.
  assert(unknown.candidates[0].reason.find("code version") != std::string::npos);

  // td::Bits256::to_hex() is uppercase. Native extraction must canonicalize
  // before the reviewed lowercase registry lookup; pure callers must not
  // silently return a valid-but-empty batch for an unnormalized address.
  assert(canonical_account_address(0, h('A')) == a('a'));
  assert(canonical_account_address(-1, h('F')) == "-1:" + h('f'));
  assert(!canonical_account_address(0, h('G')));
  assert(!canonical_account_address(0, std::string(63, 'A')));
  Tx uppercase = tx('a', 'd', 9);
  uppercase.item_address = "0:" + h('A');
  assert(!extract_from_first_included({uppercase}, r, included).valid);
  uppercase.item_address = *canonical_account_address(0, h('A'));
  auto normalized = extract_from_first_included({uppercase}, r, included);
  assert(normalized.valid && has(normalized, Signal::bid_candidate, a('a')));
  auto uppercase_registry = r;
  uppercase_registry.item_addresses = {"0:" + h('A')};
  assert(!extract_from_first_included({uppercase}, uppercase_registry, included).valid);
  uppercase_registry.item_addresses = {a('a'), "0:" + h('A')};
  assert(!extract_from_first_included({uppercase}, uppercase_registry, included).valid);
  uppercase_registry.item_addresses = {a('a'), *canonical_account_address(0, h('A'))};
  assert(!extract_from_first_included({uppercase}, uppercase_registry, included).valid);

  // Repeated tip/diff or duplicated tx: fail closed instead of double counting.
  assert(!extract_from_first_included({first, first}, r, included).valid);
  assert(!extract_from_first_included({first}, r, {r.mc_block, first.block, first.block}).valid);
  Tx fork = first;
  fork.hash = h('d');
  fork.block.root_hash = b('F');
  assert(!extract_from_first_included({first, fork}, r, {r.mc_block, first.block, fork.block}).valid);
  assert(!extract_from_first_included({first}, r, {}).valid);
  assert(!extract_from_first_included({first}, r, {first.block}).valid);
  auto wrong_mc = r;
  wrong_mc.mc_block.file_hash = b('G');
  assert(!extract_from_first_included({first}, wrong_mc, included).valid);
  // A masterchain transaction MUST match the supplied full MC ID.
  Tx mc = first;
  mc.block = r.mc_block;
  mc.item_address = "-1:" + h('a');
  mc.hash = h('f');
  assert(extract_from_first_included({mc}, r, {r.mc_block}).valid);
  mc.block.file_hash = b('G');
  assert(!extract_from_first_included({mc}, r, {r.mc_block}).valid);
  auto duplicate_registry = r;
  duplicate_registry.item_addresses.push_back(a('a'));
  duplicate_registry.limits.max_addresses = 3;
  assert(!extract_from_first_included({first}, duplicate_registry, included).valid);
  auto tiny = r;
  tiny.limits.max_candidates = 1;
  assert(!extract_from_first_included({first}, tiny, included).valid);
  tiny = r;
  tiny.limits.max_provenance_bytes = 100;
  assert(!extract_from_first_included({first}, tiny, included).valid);
  first.incoming->value_nanoton.reset();
  assert(!extract_from_first_included({first}, r, included).valid); // missing internal value != zero
}
