#pragma once
#include "Options.h"
#include <algorithm>
#include <map>
#include <set>
#include <vector>

namespace tonstat::runner {
// IDs are full identities. The native caller authenticates raw headers and
// split/merge relationships before this exact set/reachability check.
template <class Id>
void require_frontier(const std::set<Id>& old, const std::set<Id>& expected,
                      std::map<Id, std::vector<Id>> pending) {
  std::set<Id> known = old, consumed;
  for (const auto& [id, prev] : pending) {
    require(!old.count(id) && !prev.empty(), "repeated old tip or empty predecessors");
    require(std::set<Id>(prev.begin(), prev.end()).size() == prev.size(), "duplicate predecessor");
  }
  while (!pending.empty()) {
    bool progress = false;
    for (auto it = pending.begin(); it != pending.end();) {
      if (!std::all_of(it->second.begin(), it->second.end(), [&](const auto& p) { return known.count(p); })) {
        ++it; continue;
      }
      consumed.insert(it->second.begin(), it->second.end()); known.insert(it->first);
      it = pending.erase(it); progress = true;
    }
    require(progress, "first-included diff has missing predecessor or cycle");
  }
  for (const auto& p : consumed) known.erase(p);
  require(known == expected, "first-included diff does not exhaust previous/current frontier");
}
} // namespace tonstat::runner
