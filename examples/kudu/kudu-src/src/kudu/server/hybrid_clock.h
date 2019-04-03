// Copyright (c) 2013, Cloudera, inc.
// Confidential Cloudera Information: Covered by NDA.

#ifndef KUDU_SERVER_HYBRID_CLOCK_H_
#define KUDU_SERVER_HYBRID_CLOCK_H_

#include <string>

#include "kudu/gutil/ref_counted.h"
#include "kudu/server/clock.h"
#include "kudu/util/locks.h"
#include "kudu/util/metrics.h"
#include "kudu/util/status.h"

struct ntptimeval;

namespace kudu {
namespace server {

// The HybridTime clock.
class HybridClock : public Clock {
 public:
  HybridClock();

  virtual Status Init() OVERRIDE;

  // Obtains the timestamp corresponding to the current time.
  virtual Timestamp Now() OVERRIDE;

  // Obtains the timestamp corresponding to latest possible current
  // time.
  virtual Timestamp NowLatest() OVERRIDE;

  // Obtain a timestamp which is guaranteed to be later than the current time
  // on any machine in the cluster.
  //
  // NOTE: this is not a very tight bound.
  virtual Status GetGlobalLatest(Timestamp* t) OVERRIDE;

  // Updates the clock with a timestamp originating on another machine.
  virtual Status Update(const Timestamp& to_update) OVERRIDE;

  virtual void RegisterMetrics(const scoped_refptr<MetricEntity>& metric_entity) OVERRIDE;

  // HybridClock supports all external consistency modes.
  virtual bool SupportsExternalConsistencyMode(ExternalConsistencyMode mode) OVERRIDE;

  // Blocks the caller thread until the true time is after 'then'.
  // In other words, waits until the HybridClock::Now() on _all_ nodes
  // will return a value greater than 'then'.
  //
  // The incoming time 'then' is assumed to be the latest time possible
  // at the time the read was performed, i.e. 'then' = now + max_error.
  //
  // This method can be used to make Kudu behave like Spanner/TrueTime.
  // This is implemented by possibly making the caller thread wait for a
  // a certain period of time.
  //
  // As an example, the following cases might happen:
  //
  // 1 - 'then' is lower than now.earliest() -> Definitely in
  // the past, no wait necessary.
  //
  // 2 - 'then' is greater than > now.earliest(): need to wait until
  // 'then' <= now.earliest()
  //
  // Returns OK if it waited long enough or if no wait was necessary.
  //
  // Returns Status::ServiceUnavailable if the system clock was not
  // synchronized and therefore it couldn't wait out the error.
  //
  // Returns Status::TimedOut() if 'deadline' will pass before the specified
  // timestamp. NOTE: unlike most "wait" methods, this may return _immediately_
  // with a timeout, rather than actually waiting for the timeout to expire.
  // This is because, by looking at the current clock, we can know how long
  // we'll have to wait, in contrast to most Wait() methods which are waiting
  // on some external condition to become true.
  virtual Status WaitUntilAfter(const Timestamp& then,
                                const MonoTime& deadline) OVERRIDE;

  // Blocks the caller thread until the local time is after 'then'.
  // This is in contrast to the above method, which waits until the time
  // on _all_ machines is past the given time.
  //
  // Returns Status::TimedOut() if 'deadline' will pass before the specified
  // timestamp. NOTE: unlike most "wait" methods, this may return _immediately_
  // with a timeout. See WaitUntilAfter() for details.
  virtual Status WaitUntilAfterLocally(const Timestamp& then,
                                       const MonoTime& deadline) OVERRIDE;

  // Return true if the given time has passed (i.e any future call
  // to Now() would return a higher value than t).
  //
  // NOTE: this only refers to the _local_ clock, and is not a guarantee
  // that other nodes' clocks have definitely passed this timestamp.
  // This is in contrast to WaitUntilAfter() above.
  virtual bool IsAfter(Timestamp t) OVERRIDE;

  // Obtains the timestamp corresponding to the current time and the associated
  // error in micros. This may fail if the clock is unsynchronized or synchronized
  // but the error is too high and, since we can't do anything about it,
  // LOG(FATAL)'s in that case.
  void NowWithError(Timestamp* timestamp, uint64_t* max_error_usec);

  virtual std::string Stringify(Timestamp timestamp) OVERRIDE;

  // Static encoding/decoding methods for timestamps. Public mostly
  // for testing/debugging purposes.

  // Returns the logical value embedded in 'timestamp'
  static uint64_t GetLogicalValue(const Timestamp& timestamp);

  // Returns the physical value embedded in 'timestamp', in microseconds.
  static uint64_t GetPhysicalValueMicros(const Timestamp& timestamp);

  // Obtains a new Timestamp with the logical value zeroed out.
  static Timestamp TimestampFromMicroseconds(uint64_t micros);

  // Obtains a new Timestamp that embeds both the physical and logical values.
  static Timestamp TimestampFromMicrosecondsAndLogicalValue(uint64_t micros,
                                                            uint64_t logical_value);

  // Creates a new timestamp whose physical time is GetPhysicalValue(original) +
  // 'micros_to_add' and which retains the same logical value.
  static Timestamp AddPhysicalTimeToTimestamp(const Timestamp& original,
                                              const MonoDelta& to_add);

  // Outputs a string containing the physical and logical values of the timestamp,
  // separated.
  static std::string StringifyTimestamp(const Timestamp& timestamp);

 private:
  uint64_t GetTimeUsecs(ntptimeval* timeval);

  // Used to get the timestamp for metrics.
  uint64_t NowForMetrics();

  // Used to get the current error, for metrics.
  uint64_t ErrorForMetrics();

  uint64_t divisor_;

  double tolerance_adjustment_;

  mutable simple_spinlock lock_;

  // the last clock read/update, in microseconds.
  uint64_t last_usec_;
  // the next logical value to be assigned to a timestamp
  uint64_t next_logical_;

  // How many bits to left shift a microseconds clock read. The remainder
  // of the timestamp will be reserved for logical values.
  static const int kBitsToShift;

  // Mask to extract the pure logical bits.
  static const uint64_t kLogicalBitMask;

  static const uint64_t kNanosPerSec;

  // The scaling factor used to obtain ppms. From the adjtimex source:
  // "scale factor used by adjtimex freq param.  1 ppm = 65536"
  static const double kAdjtimexScalingFactor;

  enum State {
    kNotInitialized,
    kInitialized
  };

  State state_;

  // Clock metrics are set to detach to their last value. This means
  // that, during our destructor, we'll need to access other class members
  // declared above this. Hence, this member must be declared last.
  FunctionGaugeDetacher metric_detacher_;
};

}  // namespace server
}  // namespace kudu

#endif /* KUDU_SERVER_HYBRID_CLOCK_H_ */
