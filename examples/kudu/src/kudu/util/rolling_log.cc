// Copyright (c) 2015, Cloudera, inc.
// Confidential Cloudera Information: Covered by NDA.

#include "kudu/util/rolling_log.h"

#include <unistd.h>
#include <sys/types.h>

#include <iomanip>
#include <ostream>
#include <string>
#include <zlib.h>

#include "kudu/gutil/strings/numbers.h"
#include "kudu/gutil/strings/substitute.h"
#include "kudu/gutil/walltime.h"
#include "kudu/util/env.h"
#include "kudu/util/net/net_util.h"
#include "kudu/util/path_util.h"
#include "kudu/util/thread_restrictions.h"
#include "kudu/util/user.h"

using std::ostringstream;
using std::setw;
using std::string;
using strings::Substitute;

static const int kDefaultSizeLimitBytes = 64 * 1024 * 1024; // 64MB

namespace kudu {

RollingLog::RollingLog(Env* env,
                       const string& log_dir,
                       const string& log_name)
  : env_(env),
    log_dir_(log_dir),
    log_name_(log_name),
    size_limit_bytes_(kDefaultSizeLimitBytes),
    compress_after_close_(true) {
}

RollingLog::~RollingLog() {
  WARN_NOT_OK(Close(), "Unable to close RollingLog");
}

void RollingLog::SetSizeLimitBytes(int64_t size) {
  CHECK_GT(size, 0);
  size_limit_bytes_ = size;
}

void RollingLog::SetCompressionEnabled(bool compress) {
  compress_after_close_ = compress;
}

string RollingLog::GetLogFileName(int sequence) const {
  ostringstream str;

  // 1. Program name.
  str << google::ProgramInvocationShortName();

  // 2. Host name.
  string hostname;
  Status s = GetHostname(&hostname);
  if (!s.ok()) {
    hostname = "unknown_host";
  }
  str << "." << hostname;

  // 3. User name.
  string user_name;
  s = GetLoggedInUser(&user_name);
  if (!s.ok()) {
    user_name = "unknown_user";
  }
  str << "." << user_name;

  // 4. Log name.
  str << "." << log_name_;

  // 5. Timestamp.
  // Implementation cribbed from glog/logging.cc
  time_t time = static_cast<time_t>(WallTime_Now());
  struct ::tm tm_time;
  localtime_r(&time, &tm_time);

  str << ".";
  str.fill('0');
  str << 1900+tm_time.tm_year
      << setw(2) << 1+tm_time.tm_mon
      << setw(2) << tm_time.tm_mday
      << '-'
      << setw(2) << tm_time.tm_hour
      << setw(2) << tm_time.tm_min
      << setw(2) << tm_time.tm_sec;
  str.clear(); // resets formatting flags

  // 6. Sequence number.
  str << "." << sequence;

  // 7. Pid.
  str << "." << getpid();

  return str.str();
}

Status RollingLog::Open() {
  CHECK(!file_);

  for (int sequence = 0; ; sequence++) {

    string path = JoinPathSegments(log_dir_,
                                   GetLogFileName(sequence));

    WritableFileOptions opts;
    // No need to worry about mmap IO for performance, etc, and we'd
    // rather not SIGBUS on an IO error.
    opts.mmap_file = false;
    // Logs aren't worth the performance cost of durability.
    opts.sync_on_close = false;
    opts.mode = Env::CREATE_NON_EXISTING;

    Status s = env_->NewWritableFile(opts, path, &file_);
    if (s.IsAlreadyPresent()) {
      // We already rolled once at this same timestamp.
      // Try again with a new sequence number.
      continue;
    }
    RETURN_NOT_OK(s);

    VLOG(1) << "Rolled " << log_name_ << " log to new file: " << path;
    break;
  }
  return Status::OK();
}

Status RollingLog::Close() {
  if (!file_) {
    return Status::OK();
  }
  string path = file_->filename();
  RETURN_NOT_OK_PREPEND(file_->Close(),
                        Substitute("Unable to close $0", path));
  file_.reset();
  if (compress_after_close_) {
    WARN_NOT_OK(CompressFile(path), "Unable to compress old log file");
  }
  return Status::OK();
}

Status RollingLog::Append(StringPiece s) {
  if (!file_) {
    RETURN_NOT_OK_PREPEND(Open(), "Unable to open log");
  }

  if (file_->Size() + s.size() > size_limit_bytes_) {
    RETURN_NOT_OK_PREPEND(Close(), "Unable to roll log");
    RETURN_NOT_OK_PREPEND(Open(), "Unable to roll log");
  }
  RETURN_NOT_OK(file_->Append(s));
  return Status::OK();
}

namespace {

Status GzClose(gzFile f) {
  int err = gzclose(f);
  switch (err) {
    case Z_OK:
      return Status::OK();
    case Z_STREAM_ERROR:
      return Status::InvalidArgument("Stream not valid");
    case Z_ERRNO:
      return Status::IOError("IO Error closing stream");
    case Z_MEM_ERROR:
      return Status::RuntimeError("Out of memory");
    case Z_BUF_ERROR:
      return Status::IOError("read ended in the middle of a stream");
    default:
      return Status::IOError("Unknown zlib error", SimpleItoa(err));
  }
}

class ScopedGzipCloser {
 public:
  explicit ScopedGzipCloser(gzFile f)
    : file_(f) {
  }

  ~ScopedGzipCloser() {
    if (file_) {
      WARN_NOT_OK(GzClose(file_), "Unable to close gzip stream");
    }
  }

  void Cancel() {
    file_ = NULL;
  }

 private:
  gzFile file_;
};
} // anonymous namespace

// We implement CompressFile() manually using zlib APIs rather than forking
// out to '/bin/gzip' since fork() can be expensive on processes that use a large
// amount of memory. During the time of the fork, other threads could end up
// blocked. Implementing it using the zlib stream APIs isn't too much code
// and is less likely to be problematic.
Status RollingLog::CompressFile(const std::string& path) const {
  gscoped_ptr<SequentialFile> in_file;
  RETURN_NOT_OK_PREPEND(env_->NewSequentialFile(path, &in_file),
                        "Unable to open input file to compress");

  string gz_path = path + ".gz";
  gzFile gzf = gzopen(gz_path.c_str(), "w");
  if (!gzf) {
    return Status::IOError("Unable to open gzip stream");
  }

  ScopedGzipCloser closer(gzf);

  // Loop reading data from the input file and writing to the gzip stream.
  uint8_t buf[32 * 1024];
  while (true) {
    Slice result;
    RETURN_NOT_OK_PREPEND(in_file->Read(arraysize(buf), &result, buf),
                          "Unable to read from gzip input");
    if (result.size() == 0) {
      break;
    }
    int n = gzwrite(gzf, result.data(), result.size());
    if (n == 0) {
      int errnum;
      return Status::IOError("Unable to write to gzip output",
                             gzerror(gzf, &errnum));
    }
  }
  closer.Cancel();
  RETURN_NOT_OK_PREPEND(GzClose(gzf),
                        "Unable to close gzip output");

  WARN_NOT_OK(env_->DeleteFile(path),
              "Unable to delete gzip input file after compression");
  return Status::OK();
}

} // namespace kudu
