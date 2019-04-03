// Copyright (c) 2014, Cloudera, inc.
// Confidential Cloudera Information: Covered by NDA.

#include "kudu/util/failure_detector.h"

#include <boost/foreach.hpp>
#include <glog/logging.h>
#include <tr1/unordered_map>

#include "kudu/gutil/map-util.h"
#include "kudu/gutil/stl_util.h"
#include "kudu/gutil/strings/substitute.h"
#include "kudu/util/locks.h"
#include "kudu/util/random_util.h"
#include "kudu/util/status.h"
#include "kudu/util/thread.h"

namespace kudu {

using std::tr1::unordered_map;
using strings::Substitute;

const int64_t RandomizedFailureMonitor::kMinWakeUpTimeMillis = 10;

TimedFailureDetector::TimedFailureDetector(MonoDelta failure_period)
    : failure_period_(failure_period) {
}

TimedFailureDetector::~TimedFailureDetector() {
  STLDeleteValues(&nodes_);
}

Status TimedFailureDetector::Track(const string& name,
                                   const MonoTime& now,
                                   const FailureDetectedCallback& callback) {
  lock_guard<simple_spinlock> lock(&lock_);
  gscoped_ptr<Node> node(new Node);
  node->permanent_name = name;
  node->callback = callback;
  node->last_heard_of = now;
  node->status = ALIVE;
  if (!InsertIfNotPresent(&nodes_, name, node.get())) {
    return Status::AlreadyPresent(
        Substitute("Node with name '$0' is already being monitored", name));
  }
  ignore_result(node.release());
  return Status::OK();
}

Status TimedFailureDetector::UnTrack(const string& name) {
  lock_guard<simple_spinlock> lock(&lock_);
  Node* node = EraseKeyReturnValuePtr(&nodes_, name);
  if (PREDICT_FALSE(node == NULL)) {
    return Status::NotFound(Substitute("Node with name '$0' not found", name));
  }
  delete node;
  return Status::OK();
}

bool TimedFailureDetector::IsTracking(const std::string& name) {
  lock_guard<simple_spinlock> lock(&lock_);
  return ContainsKey(nodes_, name);
}

Status TimedFailureDetector::MessageFrom(const std::string& name, const MonoTime& now) {
  VLOG(3) << "Received message from " << name << " at " << now.ToString();
  lock_guard<simple_spinlock> lock(&lock_);
  Node* node = FindPtrOrNull(nodes_, name);
  if (node == NULL) {
    VLOG(1) << "Not tracking node: " << name;
    return Status::NotFound(Substitute("Message from unknown node '$0'", name));
  }
  node->last_heard_of = now;
  node->status = ALIVE;
  return Status::OK();
}

FailureDetector::NodeStatus TimedFailureDetector::GetNodeStatusUnlocked(const std::string& name,
                                                                        const MonoTime& now) {
  Node* node = FindOrDie(nodes_, name);
  if (now.GetDeltaSince(node->last_heard_of).MoreThan(failure_period_)) {
    node->status = DEAD;
  }
  return node->status;
}

void TimedFailureDetector::CheckForFailures(const MonoTime& now) {
  typedef unordered_map<string, FailureDetectedCallback> CallbackMap;
  CallbackMap callbacks;
  {
    lock_guard<simple_spinlock> lock(&lock_);
    BOOST_FOREACH(const NodeMap::value_type& entry, nodes_) {
      if (GetNodeStatusUnlocked(entry.first, now) == DEAD) {
        InsertOrDie(&callbacks, entry.first, entry.second->callback);
      }
    }
  }
  // Invoke failure callbacks outside of lock.
  BOOST_FOREACH(const CallbackMap::value_type& entry, callbacks) {
    const string& node_name = entry.first;
    const FailureDetectedCallback& callback = entry.second;
    callback.Run(node_name, Status::RemoteError(Substitute("Node '$0' failed", node_name)));
  }
}

RandomizedFailureMonitor::RandomizedFailureMonitor(uint32_t random_seed,
                                                   int64_t period_mean_millis,
                                                   int64_t period_stddev_millis)
    : period_mean_millis_(period_mean_millis),
      period_stddev_millis_(period_stddev_millis),
      random_(random_seed),
      run_latch_(0),
      shutdown_(false) {
}

RandomizedFailureMonitor::~RandomizedFailureMonitor() {
  Shutdown();
}

Status RandomizedFailureMonitor::Start() {
  CHECK(!thread_);
  run_latch_.Reset(1);
  return Thread::Create("failure-monitors", "failure-monitor",
                        &RandomizedFailureMonitor::RunThread,
                        this, &thread_);
}

void RandomizedFailureMonitor::Shutdown() {
  if (!thread_) {
    return;
  }

  {
    lock_guard<simple_spinlock> l(&lock_);
    if (shutdown_) {
      return;
    }
    shutdown_ = true;
  }

  run_latch_.CountDown();
  CHECK_OK(ThreadJoiner(thread_.get()).Join());
  thread_.reset();
}

Status RandomizedFailureMonitor::MonitorFailureDetector(const string& name,
                                                        const scoped_refptr<FailureDetector>& fd) {
  lock_guard<simple_spinlock> l(&lock_);
  bool inserted = InsertIfNotPresent(&fds_, name, fd);
  if (PREDICT_FALSE(!inserted)) {
    return Status::AlreadyPresent(Substitute("Already monitoring failure detector '$0'", name));
  }
  return Status::OK();
}

Status RandomizedFailureMonitor::UnmonitorFailureDetector(const string& name) {
  lock_guard<simple_spinlock> l(&lock_);
  int count = fds_.erase(name);
  if (PREDICT_FALSE(count == 0)) {
    return Status::NotFound(Substitute("Failure detector '$0' not found", name));
  }
  return Status::OK();
}

void RandomizedFailureMonitor::RunThread() {
  VLOG(1) << "Failure monitor thread starting";

  while (true) {
    int64_t wait_millis = random_.Normal(period_mean_millis_, period_stddev_millis_);
    if (wait_millis < kMinWakeUpTimeMillis) {
      wait_millis = kMinWakeUpTimeMillis;
    }

    MonoDelta wait_delta = MonoDelta::FromMilliseconds(wait_millis);
    VLOG(3) << "RandomizedFailureMonitor sleeping for: " << wait_delta.ToString();
    if (run_latch_.WaitFor(wait_delta)) {
      // CountDownLatch reached 0.
      lock_guard<simple_spinlock> lock(&lock_);
      // Check if we were told to shutdown.
      if (shutdown_) {
        // Latch fired: exit loop.
        VLOG(1) << "RandomizedFailureMonitor thread shutting down";
        return;
      }
    }

    // Take a copy of the FD map under the lock.
    FDMap fds_copy;
    {
      lock_guard<simple_spinlock> l(&lock_);
      fds_copy = fds_;
    }

    MonoTime now = MonoTime::Now(MonoTime::FINE);
    BOOST_FOREACH(const FDMap::value_type& entry, fds_copy) {
      entry.second->CheckForFailures(now);
    }
  }
}

}  // namespace kudu
