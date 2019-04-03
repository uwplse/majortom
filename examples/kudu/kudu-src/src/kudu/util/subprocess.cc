// Copyright (c) 2014, Cloudera, inc.
// Confidential Cloudera Information: Covered by NDA.

#include "kudu/util/subprocess.h"

#include <boost/foreach.hpp>
#include <dirent.h>
#include <glog/logging.h>
#include <fcntl.h>
#include <tr1/memory>
#include <string>
#include <vector>
#include <signal.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "kudu/gutil/once.h"
#include "kudu/gutil/port.h"
#include "kudu/gutil/strings/join.h"
#include "kudu/gutil/strings/numbers.h"
#include "kudu/gutil/strings/substitute.h"
#include "kudu/util/debug-util.h"
#include "kudu/util/errno.h"
#include "kudu/util/status.h"

using std::string;
using std::tr1::shared_ptr;
using std::vector;
using strings::Substitute;

namespace kudu {

namespace {

static const char* kProcSelfFd = "/proc/self/fd";

void DisableSigPipe() {
  struct sigaction act;

  act.sa_handler = SIG_IGN;
  sigemptyset(&act.sa_mask);
  act.sa_flags = 0;
  PCHECK(sigaction(SIGPIPE, &act, NULL) == 0);
}

void EnsureSigPipeDisabled() {
  static GoogleOnceType once = GOOGLE_ONCE_INIT;
  GoogleOnceInit(&once, &DisableSigPipe);
}

// Since opendir() calls malloc(), this must be called before fork().
// This function is not async-signal-safe.
Status OpenProcFdDir(DIR** dir) {
  *dir = opendir(kProcSelfFd);
  if (PREDICT_FALSE(dir == NULL)) {
    return Status::IOError(Substitute("opendir(\"$0\") failed", kProcSelfFd),
                           ErrnoToString(errno), errno);
  }
  return Status::OK();
}

// Close the directory stream opened by OpenProcFdDir().
// This function is not async-signal-safe.
void CloseProcFdDir(DIR* dir) {
  if (PREDICT_FALSE(closedir(dir) == -1)) {
    LOG(WARNING) << "Unable to close fd dir: "
                 << Status::IOError(Substitute("closedir(\"$0\") failed", kProcSelfFd),
                                    ErrnoToString(errno), errno).ToString();
  }
}

// Close all open file descriptors other than stdin, stderr, stdout.
// Expects a directory stream created by OpenProdFdDir() as a parameter.
// This function is called after fork() and must not call malloc().
// The rule of thumb is to only call async-signal-safe functions in such cases
// if at all possible.
void CloseNonStandardFDs(DIR* fd_dir) {
#ifndef __linux__
#error This function is Linux-specific.
#endif
  // This is implemented by iterating over the open file descriptors
  // rather than using sysconf(SC_OPEN_MAX) -- the latter is error prone
  // since it may not represent the highest open fd if the fd soft limit
  // has changed since the process started. This should also be faster
  // since iterating over all possible fds is likely to cause 64k+ syscalls
  // in typical configurations.
  //
  // Note also that this doesn't use any of the Env utility functions, to
  // make it as lean and mean as possible -- this runs in the subprocess
  // after a fork, so there's some possibility that various global locks
  // inside malloc() might be held, so allocating memory is a no-no.
  PCHECK(fd_dir != NULL);
  int dir_fd = dirfd(fd_dir);

  struct dirent64 *ent;
  // readdir64() is not reentrant (it uses a static buffer) and it also
  // locks fd_dir->lock, so it must not be called in a multi-threaded
  // environment and is certainly not async-signal-safe.
  // However, it appears to be safe to call right after fork(), since only one
  // thread exists in the child process at that time. It also does not call
  // malloc() or free(). We could use readdir64_r() instead, but all that
  // buys us is reentrancy, and not async-signal-safety, due to the use of
  // dir->lock, so seems not worth the added complexity in lifecycle & plumbing.
  while ((ent = readdir64(fd_dir)) != NULL) {
    uint32_t fd;
    if (!safe_strtou32(ent->d_name, &fd)) continue;
    if (!(fd == STDIN_FILENO  ||
          fd == STDOUT_FILENO ||
          fd == STDERR_FILENO ||
          fd == dir_fd))  {
      close(fd);
    }
  }
}

} // anonymous namespace

Subprocess::Subprocess(const string& program,
                       const vector<string>& argv)
  : program_(program),
    argv_(argv),
    state_(kNotStarted),
    child_pid_(-1),
    fd_state_(),
    child_fds_() {
  fd_state_[STDIN_FILENO]   = PIPED;
  fd_state_[STDOUT_FILENO]  = SHARED;
  fd_state_[STDERR_FILENO]  = SHARED;
  child_fds_[STDIN_FILENO]  = -1;
  child_fds_[STDOUT_FILENO] = -1;
  child_fds_[STDERR_FILENO] = -1;
}

Subprocess::~Subprocess() {
  if (state_ == kRunning) {
    LOG(WARNING) << "Child process " << child_pid_
                 << "(" << JoinStrings(argv_, " ") << ") "
                 << " was orphaned. Sending SIGKILL...";
    WARN_NOT_OK(Kill(SIGKILL), "Failed to send SIGKILL");
    int junk = 0;
    WARN_NOT_OK(Wait(&junk), "Failed to Wait()");
  }

  for (int i = 0; i < 3; ++i) {
    if (fd_state_[i] == PIPED && child_fds_[i] >= 0) {
      close(child_fds_[i]);
    }
  }
}

void Subprocess::SetFdShared(int stdfd, bool share) {
  CHECK_EQ(state_, kNotStarted);
  CHECK_NE(fd_state_[stdfd], DISABLED);
  fd_state_[stdfd] = share? SHARED : PIPED;
}

void Subprocess::DisableStderr() {
  CHECK_EQ(state_, kNotStarted);
  fd_state_[STDERR_FILENO] = DISABLED;
}

void Subprocess::DisableStdout() {
  CHECK_EQ(state_, kNotStarted);
  fd_state_[STDOUT_FILENO] = DISABLED;
}

static void RedirectToDevNull(int fd) {
  // We must not close stderr or stdout, because then when a new file descriptor
  // gets opened, it might get that fd number.  (We always allocate the lowest
  // available file descriptor number.)  Instead, we reopen that fd as
  // /dev/null.
  int dev_null = open("/dev/null", O_WRONLY);
  if (dev_null < 0) {
    PLOG(WARNING) << "failed to open /dev/null";
  } else {
    PCHECK(dup2(dev_null, fd));
  }
}

Status Subprocess::Start() {
  CHECK_EQ(state_, kNotStarted);
  EnsureSigPipeDisabled();

  if (argv_.size() < 1) {
    return Status::InvalidArgument("argv must have at least one elem");
  }

  vector<char*> argv_ptrs;
  BOOST_FOREACH(const string& arg, argv_) {
    argv_ptrs.push_back(const_cast<char*>(arg.c_str()));
  }
  argv_ptrs.push_back(NULL);

  // Pipe from caller process to child's stdin
  // [0] = stdin for child, [1] = how parent writes to it
  int child_stdin[2] = {-1, -1};
  if (fd_state_[STDIN_FILENO] == PIPED) {
    PCHECK(pipe2(child_stdin, O_CLOEXEC) == 0);
  }
  // Pipe from child's stdout back to caller process
  // [0] = how parent reads from child's stdout, [1] = how child writes to it
  int child_stdout[2] = {-1, -1};
  if (fd_state_[STDOUT_FILENO] == PIPED) {
    PCHECK(pipe2(child_stdout, O_CLOEXEC) == 0);
  }
  // Pipe from child's stderr back to caller process
  // [0] = how parent reads from child's stderr, [1] = how child writes to it
  int child_stderr[2] = {-1, -1};
  if (fd_state_[STDERR_FILENO] == PIPED) {
    PCHECK(pipe2(child_stderr, O_CLOEXEC) == 0);
  }

  DIR* fd_dir = NULL;
  RETURN_NOT_OK_PREPEND(OpenProcFdDir(&fd_dir), "Unable to open fd dir");
  shared_ptr<DIR> fd_dir_closer(fd_dir, CloseProcFdDir);

  int ret = fork();
  if (ret == -1) {
    return Status::RuntimeError("Unable to fork", ErrnoToString(errno), errno);
  }
  if (ret == 0) { // We are the child
    // Send the child a SIGTERM when the parent dies. This is done as early
    // as possible in the child's life to prevent any orphaning whatsoever
    // (e.g. from KUDU-402).
    //
    // TODO: prctl(PR_SET_PDEATHSIG) is Linux-specific, look into portable ways
    // to prevent orphans when parent is killed.
    prctl(PR_SET_PDEATHSIG, SIGTERM);

    // stdin
    if (fd_state_[STDIN_FILENO] == PIPED) {
      PCHECK(dup2(child_stdin[0], STDIN_FILENO) == STDIN_FILENO);
    }
    // stdout
    switch (fd_state_[STDOUT_FILENO]) {
    case PIPED: {
      PCHECK(dup2(child_stdout[1], STDOUT_FILENO) == STDOUT_FILENO);
      break;
    }
    case DISABLED: {
      RedirectToDevNull(STDOUT_FILENO);
      break;
    }
    default: break;
    }
    // stderr
    switch (fd_state_[STDERR_FILENO]) {
    case PIPED: {
      PCHECK(dup2(child_stderr[1], STDERR_FILENO) == STDERR_FILENO);
      break;
    }
    case DISABLED: {
      RedirectToDevNull(STDERR_FILENO);
      break;
    }
    default: break;
    }

    CloseNonStandardFDs(fd_dir);

    execvp(program_.c_str(), &argv_ptrs[0]);
    PLOG(WARNING) << "Couldn't exec";
    _exit(errno);
  } else {
    // We are the parent
    child_pid_ = ret;
    // Close child's side of the pipes
    if (fd_state_[STDIN_FILENO]  == PIPED) close(child_stdin[0]);
    if (fd_state_[STDOUT_FILENO] == PIPED) close(child_stdout[1]);
    if (fd_state_[STDERR_FILENO] == PIPED) close(child_stderr[1]);
    // Keep parent's side of the pipes
    child_fds_[STDIN_FILENO]  = child_stdin[1];
    child_fds_[STDOUT_FILENO] = child_stdout[0];
    child_fds_[STDERR_FILENO] = child_stderr[0];
  }

  state_ = kRunning;
  return Status::OK();
}

Status Subprocess::DoWait(int* ret, int options) {
  if (state_ == kExited) {
    *ret = cached_rc_;
    return Status::OK();
  }
  CHECK_EQ(state_, kRunning);

  int rc = waitpid(child_pid_, ret, options);
  if (rc == -1) {
    return Status::RuntimeError("Unable to wait on child",
                                ErrnoToString(errno),
                                errno);
  }
  if ((options & WNOHANG) && rc == 0) {
    return Status::TimedOut("");
  }

  CHECK_EQ(rc, child_pid_);
  child_pid_ = -1;
  cached_rc_ = *ret;
  state_ = kExited;
  return Status::OK();
}

Status Subprocess::Kill(int signal) {
  CHECK_EQ(state_, kRunning);
  if (kill(child_pid_, signal) != 0) {
    return Status::RuntimeError("Unable to kill",
                                ErrnoToString(errno),
                                errno);
  }
  return Status::OK();
}

int Subprocess::CheckAndOffer(int stdfd) const {
  CHECK_EQ(state_, kRunning);
  CHECK_EQ(fd_state_[stdfd], PIPED);
  return child_fds_[stdfd];
}

int Subprocess::ReleaseChildFd(int stdfd) {
  CHECK_EQ(state_, kRunning);
  CHECK_GE(child_fds_[stdfd], 0);
  CHECK_EQ(fd_state_[stdfd], PIPED);
  int ret = child_fds_[stdfd];
  child_fds_[stdfd] = -1;
  return ret;
}

pid_t Subprocess::pid() const {
  CHECK_EQ(state_, kRunning);
  return child_pid_;
}

} // namespace kudu
