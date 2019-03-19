// Copyright (c) 2014, Cloudera, inc.
// Confidential Cloudera Information: Covered by NDA.

#ifndef KUDU_UTIL_FAILURE_DETECTOR_H_
#define KUDU_UTIL_FAILURE_DETECTOR_H_

#include <tr1/unordered_map>
#include <string>

#include "kudu/gutil/callback.h"
#include "kudu/gutil/gscoped_ptr.h"
#include "kudu/gutil/macros.h"
#include "kudu/gutil/ref_counted.h"
#include "kudu/util/countdown_latch.h"
#include "kudu/util/monotime.h"
#include "kudu/util/locks.h"
#include "kudu/util/random.h"
#include "kudu/util/status_callback.h"

namespace kudu {
class MonoDelta;
class MonoTime;
class Status;
class Thread;

// A generic interface for failure detector implementations.
// A failure detector is responsible for deciding whether a certain server is dead or alive.
class FailureDetector : public RefCountedThreadSafe<FailureDetector> {
 public:
  enum NodeStatus {
    DEAD,
    ALIVE
  };
  typedef std::tr1::unordered_map<std::string, NodeStatus> StatusMap;

  typedef Callback<void(const std::string& name,
                        const Status& status)> FailureDetectedCallback;

  virtual ~FailureDetector() {}

  // Registers a node with 'name' in the failure detector.
  //
  // If it returns Status::OK() the failure detector will from now
  // expect messages from the machine with 'name' and will trigger
  // 'callback' if a failure is detected.
  //
  // Returns Status::AlreadyPresent() if a machine with 'name' is
  // already registered in this failure detector.
  virtual Status Track(const std::string& name,
                       const MonoTime& now,
                       const FailureDetectedCallback& callback) = 0;

  // Stops tracking node with 'name'.
  virtual Status UnTrack(const std::string& name) = 0;

  // Return true iff the named entity is currently being tracked.
  virtual bool IsTracking(const std::string& name) = 0;

  // Records that a message from machine with 'name' was received at 'now'.
  virtual Status MessageFrom(const std::string& name, const MonoTime& now) = 0;

  // Checks the failure status of each tracked node. If the failure criteria is
  // met, the failure callback is invoked.
  virtual void CheckForFailures(const MonoTime& now) = 0;
};

// A simple failure detector implementation that considers a node dead
// when they have not reported by a certain time interval.
class TimedFailureDetector : public FailureDetector {
 public:
  // Some monitorable entity.
  struct Node {
    std::string permanent_name;
    MonoTime last_heard_of;
    FailureDetectedCallback callback;
    NodeStatus status;
  };

  explicit TimedFailureDetector(MonoDelta failure_period);
  virtual ~TimedFailureDetector();

  virtual Status Track(const std::string& name,
                       const MonoTime& now,
                       const FailureDetectedCallback& callback) OVERRIDE;

  virtual Status UnTrack(const std::string& name) OVERRIDE;

  virtual bool IsTracking(const std::string& name) OVERRIDE;

  virtual Status MessageFrom(const std::string& name, const MonoTime& now) OVERRIDE;

  virtual void CheckForFailures(const MonoTime& now) OVERRIDE;

 private:
  typedef std::tr1::unordered_map<std::string, Node*> NodeMap;

  // Check if the named failure detector has failed.
  // Does not invoke the callback.
  FailureDetector::NodeStatus GetNodeStatusUnlocked(const std::string& name,
                                                    const MonoTime& now);

  const MonoDelta failure_period_;
  mutable simple_spinlock lock_;
  NodeMap nodes_;

  DISALLOW_COPY_AND_ASSIGN(TimedFailureDetector);
};

// A randomized failure monitor that wakes up in normally-distributed intervals
// and runs CheckForFailures() on each failure detector it monitors.
//
// The wake up interval is defined by a normal distribution with the specified
// mean and standard deviation, in milliseconds, with minimum possible value
// pinned at kMinWakeUpTimeMillis.
//
// We use a random wake up interval to avoid thundering herd / lockstep problems
// when multiple nodes react to the failure of another node.
class RandomizedFailureMonitor {
 public:
  // The minimum time the FailureMonitor will wait.
  static const int64_t kMinWakeUpTimeMillis;

  RandomizedFailureMonitor(uint32_t random_seed,
                           int64_t period_mean_millis,
                           int64_t period_std_dev_millis);
  ~RandomizedFailureMonitor();

  // Starts the failure monitor.
  Status Start();

  // Stops the failure monitor.
  void Shutdown();

  // Adds a failure detector to be monitored.
  Status MonitorFailureDetector(const std::string& name,
                                const scoped_refptr<FailureDetector>& fd);

  // Unmonitors the failure detector with the specified name.
  Status UnmonitorFailureDetector(const std::string& name);

 private:
  typedef std::tr1::unordered_map<std::string, scoped_refptr<FailureDetector> > FDMap;

  // Runs the monitor thread.
  void RunThread();

  // Mean & std. deviation of random period to sleep for between checking the
  // failure detectors.
  const int64_t period_mean_millis_;
  const int64_t period_stddev_millis_;
  ThreadSafeRandom random_;

  scoped_refptr<Thread> thread_;
  CountDownLatch run_latch_;

  mutable simple_spinlock lock_;
  FDMap fds_;
  bool shutdown_; // Whether the failure monitor should shut down.

  DISALLOW_COPY_AND_ASSIGN(RandomizedFailureMonitor);
};

}  // namespace kudu

#endif /* KUDU_UTIL_FAILURE_DETECTOR_H_ */
