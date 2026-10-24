#include "Progress.h"
#include <cerrno>
#include <fcntl.h>
#include <fstream>
#include <sstream>
#include <sys/file.h>
#include <unistd.h>

namespace tonstat::runner {
namespace {
namespace fs = std::filesystem;
void sync_dir(const fs::path& p) {
  int fd = open(p.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
  require(fd >= 0, "cannot open progress directory");
  auto ok = fsync(fd) == 0; close(fd); require(ok, "directory fsync failed");
}
void write_new(const fs::path& p, const std::string& text) {
  int fd = open(p.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
  require(fd >= 0, "cannot create progress file");
  size_t off = 0;
  while (off < text.size()) {
    auto n = write(fd, text.data() + off, text.size() - off);
    if (n < 0 && errno == EINTR) continue;
    if (n <= 0) { close(fd); throw std::runtime_error("progress write failed"); }
    off += n;
  }
  auto ok = fsync(fd) == 0; close(fd); require(ok, "file fsync failed");
}
std::string read_small(const fs::path& p, uint64_t max) {
  require(!fs::is_symlink(fs::symlink_status(p)) && fs::is_regular_file(p) && fs::file_size(p) <= max,
          "unsafe/oversized progress file");
  std::ifstream in(p, std::ios::binary);
  require(bool(in), "cannot read progress file");
  std::ostringstream s; s << in.rdbuf(); require(!in.bad(), "progress read failed"); return s.str();
}
} // namespace
Progress::Progress(fs::path work, std::string scope, const std::vector<AnchorRequest>& plan,
                   uint64_t byte_limit, Digest digest)
    : root_(std::move(work)), scope_id_(digest(scope)), limit_(byte_limit), digest_(std::move(digest)) {
  lock_ = open((root_ / "runner.lock").c_str(), O_RDWR | O_CREAT | O_NOFOLLOW, 0600);
  require(lock_ >= 0, "cannot create runner lock");
  if (flock(lock_, LOCK_EX | LOCK_NB) != 0) { close(lock_); lock_ = -1; throw std::runtime_error("workdir in use"); }
  try {
    auto scope_file = root_ / "scope.txt";
    if (fs::exists(scope_file)) require(read_small(scope_file, 32 * 1024 * 1024) == scope, "different scope in workdir");
    else { write_new(scope_file, scope); sync_dir(root_); }
    bool gap = false;
    for (const auto& a : plan) {
      require(plan_.empty() || a.seqno > plan_.back(), "duplicate/unordered plan scope");
      plan_.push_back(a.seqno);
      auto dir = root_ / (std::to_string(a.seqno) + ".committed");
      if (!fs::exists(dir)) { gap = true; continue; }
      require(!gap && !fs::is_symlink(fs::symlink_status(dir)), "noncontiguous/unsafe local progress");
      std::istringstream in(read_small(dir / "receipt.txt", 4 * 1024 * 1024));
      std::string saved_scope, id, checksum, line;
      require(bool(std::getline(in, saved_scope)) && bool(std::getline(in, id)) && bool(std::getline(in, checksum)),
              "truncated receipt");
      require(saved_scope == scope_id_ && !id.empty(), "receipt scope mismatch");
      require(digest_(read_small(dir / "facts.ndjson", limit_)) == checksum, "committed facts checksum mismatch");
      size_t n = 0;
      while (std::getline(in, line)) {
        require(!line.empty() && blocks_.insert(line).second, "duplicate block scope in committed batches"); ++n;
      }
      require(n > 0, "empty committed inventory");
      done_.emplace(a.seqno, id);
    }
  } catch (...) { close(lock_); lock_ = -1; throw; }
}
Progress::~Progress() { if (lock_ >= 0) close(lock_); }
bool Progress::completed(uint32_t seqno, const std::string& id) const {
  auto it = done_.find(seqno);
  if (it == done_.end()) return false;
  require(it->second == id, "resumed MC full ID differs from committed source"); return true;
}
void Progress::commit(const Commit& b) {
  require(done_.size() < plan_.size() && plan_[done_.size()] == b.seqno, "out-of-order/duplicate anchor commit");
  require(!b.mc_id.empty() && b.mc_id.find('\n') == std::string::npos && !b.ndjson.empty() &&
              b.ndjson.back() == '\n' && b.ndjson.size() <= limit_, "invalid/budget-exceeding facts batch");
  std::set<std::string> incoming;
  for (const auto& key : b.block_coordinates)
    require(!key.empty() && key.find('\n') == std::string::npos && incoming.insert(key).second && !blocks_.count(key),
            "duplicate block scope across anchors");
  require(!incoming.empty(), "empty block scope");
  auto final = root_ / (std::to_string(b.seqno) + ".committed");
  auto temp = root_ / (std::to_string(b.seqno) + ".pending");
  require(!fs::exists(final), "commit directory already exists");
  // Only the runner's uncommitted transaction is disposable; never a final dir.
  if (fs::exists(temp)) {
    require(!fs::is_symlink(fs::symlink_status(temp)), "unsafe pending directory");
    fs::remove_all(temp);
  }
  fs::create_directory(temp);
  std::string receipt = scope_id_ + '\n' + b.mc_id + '\n' + digest_(b.ndjson) + '\n';
  for (const auto& key : b.block_coordinates) receipt += key + '\n';
  write_new(temp / "facts.ndjson", b.ndjson); write_new(temp / "receipt.txt", receipt);
  sync_dir(temp); fs::rename(temp, final); sync_dir(root_);
  done_.emplace(b.seqno, b.mc_id); blocks_.insert(incoming.begin(), incoming.end());
}
void Progress::failed(uint32_t seqno, const std::string& ndjson) {
  require(done_.size() < plan_.size() && plan_[done_.size()] == seqno, "out-of-order failure");
  require(!ndjson.empty() && ndjson.size() <= limit_ && ndjson.back() == '\n', "invalid failure facts");
  auto pending = root_ / (std::to_string(seqno) + ".failure.pending");
  auto final = root_ / (std::to_string(seqno) + ".failed.ndjson");
  for (const auto& p : {pending, final}) {
    if (fs::exists(p)) require(!fs::is_symlink(fs::symlink_status(p)) && fs::is_regular_file(p), "unsafe failed-attempt path");
  }
  if (fs::exists(pending)) fs::remove(pending);
  write_new(pending, ndjson); fs::rename(pending, final); sync_dir(root_);
}
} // namespace tonstat::runner
