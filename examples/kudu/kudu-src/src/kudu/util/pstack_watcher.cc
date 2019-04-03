// Copyright 2014 Cloudera Inc.
// Confidential Cloudera Information: Covered by NDA.

#include "kudu/util/pstack_watcher.h"

#include <stdio.h>
#include <string>
#include <sys/types.h>
#include <tr1/memory>
#include <unistd.h>
#include <vector>

#include "kudu/gutil/strings/substitute.h"
#include "kudu/util/errno.h"
#include "kudu/util/status.h"
#include "kudu/util/subprocess.h"

namespace kudu {

using std::string;
using std::tr1::shared_ptr;
using std::vector;
using strings::Substitute;

PstackWatcher::PstackWatcher(const MonoDelta& timeout)
  : timeout_(timeout),
    running_(true),
    cond_(&lock_) {
  CHECK_OK(Thread::Create("pstack_watcher", "pstack_watcher",
                 boost::bind(&PstackWatcher::Run, this), &thread_));
}

PstackWatcher::~PstackWatcher() {
  Shutdown();
}

void PstackWatcher::Shutdown() {
  {
    MutexLock guard(lock_);
    running_ = false;
    cond_.Broadcast();
  }
  if (thread_) {
    CHECK_OK(ThreadJoiner(thread_.get()).Join());
    thread_.reset();
  }
}

bool PstackWatcher::IsRunning() const {
  MutexLock guard(lock_);
  return running_;
}

void PstackWatcher::Wait() const {
  MutexLock lock(lock_);
  while (running_) {
    cond_.Wait();
  }
}

void PstackWatcher::Run() {
  MutexLock guard(lock_);
  if (!running_) return;
  cond_.TimedWait(timeout_);
  if (!running_) return;

  WARN_NOT_OK(DumpStacks(DUMP_FULL), "Unable to print pstack from watcher");
  running_ = false;
  cond_.Broadcast();
}

Status PstackWatcher::HasProgram(const char* progname) {
  string which("which");
  vector<string> argv;
  argv.push_back(which);
  argv.push_back(progname);
  Subprocess proc(which, argv);
  proc.DisableStderr();
  proc.DisableStdout();
  RETURN_NOT_OK_PREPEND(proc.Start(),
      Substitute("HasProgram($0): error running 'which'", progname));
  int wait_status = 0;
  RETURN_NOT_OK(proc.Wait(&wait_status));
  if ((WIFEXITED(wait_status)) && (0 == WEXITSTATUS(wait_status))) {
    return Status::OK();
  }
  return Status::NotFound(Substitute("can't find $0: exited?=$1, status=$2",
                                     progname,
                                     static_cast<bool>(WIFEXITED(wait_status)),
                                     WEXITSTATUS(wait_status)));
}

Status PstackWatcher::DumpStacks(int flags) {
  return DumpPidStacks(getpid(), flags);
}

Status PstackWatcher::DumpPidStacks(pid_t pid, int flags) {

  // Prefer GDB if available; it gives us line numbers and thread names.
  if (HasProgram("gdb").ok()) {
    return RunGdbStackDump(pid, flags);
  }

  // Otherwise, try to use pstack or gstack.
  const char *progname = NULL;
  if (HasProgram("pstack").ok()) {
    progname = "pstack";
  } else if (HasProgram("gstack").ok()) {
    progname = "gstack";
  }

  if (!progname) {
    return Status::ServiceUnavailable("Neither gdb, pstack, nor gstack appears to be installed.");
  }
  return RunPstack(progname, pid);
}

Status PstackWatcher::RunGdbStackDump(pid_t pid, int flags) {
  // Command: gdb -quiet -batch -nx -ex cmd1 -ex cmd2 /proc/$PID/exe $PID
  string prog("gdb");
  vector<string> argv;
  argv.push_back(prog);
  argv.push_back("-quiet");
  argv.push_back("-batch");
  argv.push_back("-nx");
  argv.push_back("-ex");
  argv.push_back("set print pretty on");
  argv.push_back("-ex");
  argv.push_back("info threads");
  argv.push_back("-ex");
  argv.push_back("thread apply all bt");
  if (flags & DUMP_FULL) {
    argv.push_back("-ex");
    argv.push_back("thread apply all bt full");
  }
  argv.push_back(Substitute("/proc/$0/exe", pid));
  argv.push_back(Substitute("$0", pid));
  return RunStackDump(prog, argv);
}

Status PstackWatcher::RunPstack(const std::string& progname, pid_t pid) {
  string prog(progname);
  string pid_string(Substitute("$0", pid));
  vector<string> argv;
  argv.push_back(prog);
  argv.push_back(pid_string);
  return RunStackDump(prog, argv);
}

Status PstackWatcher::RunStackDump(const string& prog, const vector<string>& argv) {
  printf("************************ BEGIN STACKS **************************\n");
  if (fflush(stdout) == EOF) {
    return Status::IOError("Unable to flush stdout", ErrnoToString(errno), errno);
  }
  Subprocess pstack_proc(prog, argv);
  RETURN_NOT_OK_PREPEND(pstack_proc.Start(), "RunStackDump proc.Start() failed");
  if (::close(pstack_proc.ReleaseChildStdinFd()) == -1) {
    return Status::IOError("Unable to close child stdin", ErrnoToString(errno), errno);
  }
  int ret;
  RETURN_NOT_OK_PREPEND(pstack_proc.Wait(&ret), "RunStackDump proc.Wait() failed");
  if (ret == -1) {
    return Status::RuntimeError("RunStackDump proc.Wait() error", ErrnoToString(errno), errno);
  }
  printf("************************* END STACKS ***************************\n");
  if (fflush(stdout) == EOF) {
    return Status::IOError("Unable to flush stdout", ErrnoToString(errno), errno);
  }

  return Status::OK();
}

} // namespace kudu
