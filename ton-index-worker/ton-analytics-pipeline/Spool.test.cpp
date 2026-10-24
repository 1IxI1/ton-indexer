#ifdef NDEBUG
#undef NDEBUG
#endif
#include "Spool.h"
#include <cassert>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <unistd.h>

using namespace tonstat::pipeline;
namespace fs = std::filesystem;
template<class F> void rejects(F f) { bool threw = false; try { f(); } catch (...) { threw = true; } assert(threw); }
// The production caller supplies TD SHA256. This deterministic test digest only
// tests the spool's immutable-content protocol, not cryptographic primitives.
std::string test_digest(const std::string& s) {
  std::uint64_t x = 1469598103934665603ULL;
  for (unsigned char c : s) { x ^= c; x *= 1099511628211ULL; }
  std::ostringstream o; o << std::hex << std::setfill('0');
  for (int i=0;i<4;++i) o << std::setw(16) << x;
  return o.str();
}
int main() {
  auto root = fs::canonical(fs::temp_directory_path()) / ("analytics-spool-test-" + std::to_string(getpid()));
  fs::create_directories(root);
  try {
    auto db = root / "db", work = root / "work", spool = root / "spool";
    fs::create_directory(db);
    rejects([&] { validate_paths(db,db/"work",spool,true); });
    rejects([&] { validate_paths(db,work,work/"spool",true); });
    fs::create_directory(work); std::ofstream(work/"production-state") << "legacy";
    rejects([&] { validate_paths(db,work,spool,true); });
    work = root/"replay"; validate_paths(db,work,spool,true); validate_paths(db,work,spool,true);
    fs::create_directory_symlink(work,root/"work-link");
    rejects([&] { validate_paths(db,root/"work-link",spool,true); });
    SpoolLimits caps{65536,16384,2};
    {
      Spool s(spool,"producer-v1",caps,test_digest);
      rejects([&] { Spool concurrent(spool,"producer-v1",caps,test_digest); });
      s.prepare(100,"full-MC-A"); s.failed(100,"full-MC-A","processor failed before commit");
      assert(!s.completed(100,"full-MC-A"));
      s.commit(100,"full-MC-A","{\"metric\":null}\n");
      assert(s.completed(100,"full-MC-A"));
      s.commit(100,"full-MC-A","{\"metric\":null}\n");
      rejects([&] { s.commit(100,"full-MC-A","{\"metric\":0}\n"); });
      rejects([&] { s.completed(100,"same-coordinate-other-hashes"); });
      s.prepare(101,"full-MC-B"); // crash after durable intent
    }
    {
      Spool s(spool,"producer-v1",caps,test_digest);
      assert(s.completed(100,"full-MC-A") && !s.completed(101,"full-MC-B"));
      s.prepare(101,"full-MC-B"); s.commit(101,"full-MC-B","{\"facts\":[]}\n");
      rejects([&] { s.prepare(102,"full-MC-C"); });
      assert(fs::exists(spool/"rescan-required.txt"));
    }
    rejects([&] { Spool different(spool,"producer-v2",caps,test_digest); });
    std::ofstream(spool/"100.committed"/"facts.ndjson") << "corrupted\n";
    { Spool s(spool,"producer-v1",caps,test_digest); rejects([&] { s.completed(100,"full-MC-A"); }); }
    {
      Spool s(root/"byte-cap","producer-v1",{30000,16384,10},test_digest);
      s.commit(1,"full-MC-one","{}\n"); s.prepare(2,"full-MC-two");
      rejects([&] { s.commit(2,"full-MC-two",std::string(16383,'x') + '\n'); });
      assert(s.completed(1,"full-MC-one") && !s.completed(2,"full-MC-two"));
      s.failed(2,"full-MC-two","byte limit");
      assert(fs::exists(root/"byte-cap/2.pending/failure.txt"));
    }
    fs::remove_all(root);
  } catch (...) { fs::remove_all(root); throw; }
}
