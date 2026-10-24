#include "Spool.h"
#include <cerrno>
#include <fcntl.h>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <sys/file.h>
#include <unistd.h>

namespace tonstat::pipeline {
namespace {
namespace fs = std::filesystem;
void check(bool ok, const char* why) { if (!ok) throw std::runtime_error(why); }
void sync_dir(const fs::path& p) {
  int fd = open(p.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
  check(fd >= 0, "cannot open spool directory");
  auto ok = fsync(fd) == 0; close(fd); check(ok, "spool directory fsync failed");
}
void write_new(const fs::path& p, const std::string& text) {
  int fd = open(p.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
  check(fd >= 0, "cannot create spool file");
  size_t pos = 0;
  while (pos < text.size()) {
    auto n = write(fd, text.data() + pos, text.size() - pos);
    if (n < 0 && errno == EINTR) continue;
    if (n <= 0) { close(fd); throw std::runtime_error("spool write failed"); }
    pos += n;
  }
  auto ok = fsync(fd) == 0; close(fd); check(ok, "spool file fsync failed");
}
void remove_owned_file(const fs::path& p) {
  if (!fs::exists(p) && !fs::is_symlink(p)) return;
  check(!fs::is_symlink(p) && fs::is_regular_file(p), "unsafe spool file");
  fs::remove(p);
}
void replace(const fs::path& p, const std::string& text) {
  auto tmp = p; tmp += ".tmp";
  remove_owned_file(tmp);
  write_new(tmp, text);
  check(!fs::is_symlink(p), "unsafe spool destination");
  fs::rename(tmp, p); sync_dir(p.parent_path());
}
std::string read(const fs::path& p, std::uint64_t cap) {
  check(!fs::is_symlink(p) && fs::is_regular_file(p) && fs::file_size(p) <= cap, "unsafe/oversized spool file");
  std::ifstream in(p, std::ios::binary); check(bool(in), "cannot read spool file");
  std::ostringstream out; out << in.rdbuf(); check(!in.bad(), "spool read failed"); return out.str();
}
bool below(const fs::path& a, const fs::path& b) {
  auto ai = a.begin();
  for (auto bi = b.begin(); bi != b.end(); ++bi, ++ai)
    if (ai == a.end() || *ai != *bi) return false;
  return true;
}
bool overlap(const fs::path& a, const fs::path& b) { return below(a,b) || below(b,a); }
void no_symlinks(const fs::path& p) {
  fs::path part;
  for (const auto& c : p) { part /= c; check(!fs::is_symlink(part), "symlink in analytics output path"); }
}
} // namespace

void validate_paths(const fs::path& db, const fs::path& work, const fs::path& spool, bool replay) {
  check(!db.empty() && !work.empty() && !spool.empty(), "analytics requires db, working-dir and spool");
  check(work.is_absolute() && spool.is_absolute(), "analytics output paths must be absolute");
  no_symlinks(work); no_symlinks(spool);
  auto d = fs::weakly_canonical(db), w = fs::weakly_canonical(work), s = fs::weakly_canonical(spool);
  check(!overlap(d,w) && !overlap(d,s) && !overlap(w,s), "analytics db/work/spool paths must be disjoint");
  if (replay) {
    if (fs::exists(w)) {
      check(fs::is_directory(w), "replay workdir is not a directory");
      if (!fs::is_empty(w))
        check(read(w / "analytics-replay-v1", 256) == "analytics-only; no legacy database\n", "workdir is not analytics-only");
    }
    fs::create_directories(w);
    if (!fs::exists(w / "analytics-replay-v1")) {
      write_new(w / "analytics-replay-v1", "analytics-only; no legacy database\n"); sync_dir(w);
    }
  }
  fs::create_directories(s);
}

Spool::Spool(fs::path root, std::string identity, SpoolLimits limits, Digest digest)
    : root_(std::move(root)), scope_(digest(identity)), limits_(limits), digest_(std::move(digest)) {
  check(limits_.entries && limits_.batch_bytes && limits_.batch_bytes <= 64ULL * 1024 * 1024 &&
        limits_.bytes >= limits_.batch_bytes + 8192, "invalid spool limits");
  no_symlinks(root_);
  fs::create_directories(root_);
  lock_ = open((root_ / "pipeline.lock").c_str(), O_RDWR | O_CREAT | O_NOFOLLOW, 0600);
  check(lock_ >= 0, "cannot open spool lock");
  if (flock(lock_, LOCK_EX | LOCK_NB)) { close(lock_); lock_ = -1; throw std::runtime_error("spool already in use"); }
  try {
    if (fs::exists(root_ / "identity.txt")) check(read(root_ / "identity.txt", 16384) == identity, "spool belongs to different producer/options");
    else { write_new(root_ / "identity.txt", identity); sync_dir(root_); }
    for (const auto& e : fs::directory_iterator(root_)) {
      check(!e.is_symlink(), "symlink in spool");
      if (e.is_directory()) {
        auto name = e.path().filename().string();
        check(name.ends_with(".pending") || name.ends_with(".committed"), "unknown directory in spool");
        check(++entries_ <= limits_.entries, "spool entry limit exceeded");
        // Reserve metadata/failure space independent of the size of the facts.
        bytes_ += 8192;
        auto facts = e.path() / "facts.ndjson";
        if (fs::exists(facts)) { check(!fs::is_symlink(facts), "unsafe facts"); bytes_ += fs::file_size(facts); }
      }
    }
    check(bytes_ <= limits_.bytes, "spool byte limit exceeded");
  } catch (...) { close(lock_); lock_ = -1; throw; }
}
Spool::~Spool() { if (lock_ >= 0) close(lock_); }
fs::path Spool::path(std::uint32_t seqno, const char* suffix) const { return root_ / (std::to_string(seqno) + suffix); }

bool Spool::completed(std::uint32_t seqno, const std::string& id) const {
  auto dir = path(seqno, ".committed");
  if (!fs::exists(dir)) return false;
  check(!fs::is_symlink(dir) && fs::is_directory(dir), "unsafe committed directory");
  auto text = read(dir / "receipt.txt", 8192);
  std::istringstream in(text); std::string scope, saved_id, checksum;
  check(bool(std::getline(in,scope)) && bool(std::getline(in,saved_id)) && bool(std::getline(in,checksum)), "incomplete receipt");
  check(scope == scope_ && saved_id == id, "conflicting MC full ID or producer scope");
  check(digest_(read(dir / "facts.ndjson", limits_.batch_bytes)) == checksum, "corrupt committed facts");
  return true;
}
void Spool::overflow(std::uint32_t seqno) {
  std::uint32_t lo = seqno, hi = seqno;
  auto p = root_ / "rescan-required.txt";
  if (fs::exists(p)) {
    std::istringstream in(read(p, 128)); std::uint32_t a,b;
    check(bool(in >> a >> b), "invalid rescan interval"); lo = std::min(lo,a); hi = std::max(hi,b);
  }
  replace(p, std::to_string(lo) + " " + std::to_string(hi) + "\n");
}
void Spool::prepare(std::uint32_t seqno, const std::string& id) {
  check(!id.empty() && id.size() < 2048 && id.find('\n') == std::string::npos, "invalid MC identity");
  if (completed(seqno,id)) return;
  auto dir = path(seqno, ".pending");
  if (fs::exists(dir)) {
    check(!fs::is_symlink(dir), "unsafe pending directory");
    check(read(dir / "identity.txt", 4096) == id + '\n', "pending full-ID conflict");
    return;
  }
  if (entries_ >= limits_.entries || bytes_ + 8192 > limits_.bytes) {
    overflow(seqno); throw std::runtime_error("spool full; rescan-required interval retained");
  }
  fs::create_directory(dir); ++entries_; bytes_ += 8192;
  write_new(dir / "identity.txt", id + '\n'); sync_dir(dir); sync_dir(root_);
}
void Spool::commit(std::uint32_t seqno, const std::string& id, const std::string& text) {
  check(!text.empty() && text.back() == '\n' && text.size() <= limits_.batch_bytes, "invalid/oversized analytics batch");
  if (completed(seqno,id)) {
    check(read(path(seqno,".committed") / "facts.ndjson", limits_.batch_bytes) == text, "conflicting duplicate MC output");
    return;
  }
  prepare(seqno,id);
  auto dir = path(seqno,".pending"); auto facts = dir / "facts.ndjson";
  auto old = fs::exists(facts) ? fs::file_size(facts) : 0;
  check(bytes_ - old + text.size() <= limits_.bytes, "spool byte capacity reached; pending receipt retained");
  remove_owned_file(facts); remove_owned_file(dir / "receipt.txt");
  bytes_ -= old;
  write_new(facts, text); bytes_ += text.size();
  write_new(dir / "receipt.txt", scope_ + '\n' + id + '\n' + digest_(text) + '\n' + "mc:" + std::to_string(seqno) + '\n');
  remove_owned_file(dir / "failure.txt");
  sync_dir(dir); fs::rename(dir,path(seqno,".committed")); sync_dir(root_);
}
void Spool::failed(std::uint32_t seqno, const std::string& id, const std::string& reason) {
  // Even a conflict with a committed coordinate must remain visible. This
  // bounded interval is conservative: replay all seqnos in it into a new spool.
  overflow(seqno);
  auto dir = path(seqno,".pending");
  if (fs::exists(dir) && !fs::is_symlink(dir))
    replace(dir / "failure.txt", id + '\n' + reason.substr(0,2048) + '\n');
}
} // namespace tonstat::pipeline
