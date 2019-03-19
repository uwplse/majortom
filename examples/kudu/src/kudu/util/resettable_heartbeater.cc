// Copyright (c) 2014, Cloudera, inc.
// Confidential Cloudera Information: Covered by NDA.

#include <glog/logging.h>

#include "kudu/util/resettable_heartbeater.h"

#include "kudu/gutil/ref_counted.h"
#include "kudu/gutil/strings/substitute.h"
#include "kudu/util/countdown_latch.h"
#include "kudu/util/locks.h"
#include "kudu/util/status.h"
#include "kudu/util/thread.h"

namespace kudu {
using std::string;

class ResettableHeartbeaterThread {
 public:
  ResettableHeartbeaterThread(const std::string& name,
                              MonoDelta period,
                              HeartbeatFunction function);

  Status Start();
  Status Stop();
  void Reset();

 private:
  void RunThread();
  bool IsCurrentThread() const;

  const string name_;

  // The heartbeat period.
  MonoDelta period_;

  // The function to call to perform the heartbeat
  HeartbeatFunction function_;

  // The actual running thread (NULL before it is started)
  scoped_refptr<kudu::Thread> thread_;

  CountDownLatch run_latch_;

  // Whether the heartbeater should shutdown.
  bool shutdown_;

  // lock that protects access to 'shutdown_' and to 'run_latch_'
  // Reset() method.
  mutable simple_spinlock lock_;
  DISALLOW_COPY_AND_ASSIGN(ResettableHeartbeaterThread);
};

ResettableHeartbeater::ResettableHeartbeater(const std::string& name,
                                             MonoDelta period,
                                             HeartbeatFunction function)
    : thread_(new ResettableHeartbeaterThread(name, period, function)) {
}

Status ResettableHeartbeater::Start() {
  return thread_->Start();
}

Status ResettableHeartbeater::Stop() {
  return thread_->Stop();
}
void ResettableHeartbeater::Reset() {
  thread_->Reset();
}

ResettableHeartbeater::~ResettableHeartbeater() {
  WARN_NOT_OK(Stop(), "Unable to stop heartbeater thread");
}

ResettableHeartbeaterThread::ResettableHeartbeaterThread(const std::string& name,
                                                         MonoDelta period,
                                                         HeartbeatFunction function)
    : name_(name),
      period_(period),
      function_(function),
      run_latch_(0),
      shutdown_(false) {
}

void ResettableHeartbeaterThread::RunThread() {
  CHECK(IsCurrentThread());
  VLOG(1) << "Heartbeater: " << name_ << " thread starting";

  while (true) {
    if (run_latch_.WaitFor(period_)) {
      // CountDownLatch reached 0
      lock_guard<simple_spinlock> lock(&lock_);
      // check if we were told to shutdown
      if (shutdown_) {
        // Latch fired -- exit loop
        VLOG(1) << "Heartbeater: " << name_ << " thread finished";
        return;
      } else {
        // otherwise it's just a reset, reset the latch
        // and continue;
        run_latch_.Reset(1);
        continue;
      }
    }

    Status s = function_();
    if (!s.ok()) {
      LOG(WARNING)<< "Failed to heartbeat in heartbeater: " << name_
      << " Status: " << s.ToString();
      continue;
    }
  }
}

bool ResettableHeartbeaterThread::IsCurrentThread() const {
  return thread_.get() == kudu::Thread::current_thread();
}

Status ResettableHeartbeaterThread::Start() {
  CHECK(thread_ == NULL);
  run_latch_.Reset(1);
  return kudu::Thread::Create("heartbeater", strings::Substitute("$0-heartbeat", name_),
                              &ResettableHeartbeaterThread::RunThread,
                              this, &thread_);
}

void ResettableHeartbeaterThread::Reset() {
  if (!thread_) {
    return;
  }
  run_latch_.CountDown();
}

Status ResettableHeartbeaterThread::Stop() {
  if (!thread_) {
    return Status::OK();
  }

  {
    lock_guard<simple_spinlock> l(&lock_);
    if (shutdown_) {
      return Status::OK();
    }
    shutdown_ = true;
  }

  run_latch_.CountDown();
  RETURN_NOT_OK(ThreadJoiner(thread_.get()).Join());
  return Status::OK();
}

}  // namespace kudu
