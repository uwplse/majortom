// Copyright (c) 2013, Cloudera, inc.
// Confidential Cloudera Information: Covered by NDA.

#include <algorithm>
#include <boost/thread/locks.hpp>
#include <glog/logging.h>
#include <sys/timex.h>

#include "kudu/server/hybrid_clock.h"

#include "kudu/gutil/bind.h"
#include "kudu/gutil/strings/substitute.h"
#include "kudu/util/debug/trace_event.h"
#include "kudu/util/errno.h"
#include "kudu/util/flag_tags.h"
#include "kudu/util/metrics.h"
#include "kudu/util/locks.h"
#include "kudu/util/status.h"

DEFINE_int32(max_clock_sync_error_usec, 10 * 1000 * 1000, // 10 secs
             "Maximum allowed clock synchronization error as reported by NTP "
             "before the server will abort.");
TAG_FLAG(max_clock_sync_error_usec, advanced);
TAG_FLAG(max_clock_sync_error_usec, runtime);

DEFINE_bool(use_hybrid_clock, true,
            "Whether HybridClock should be used as the default clock"
            " implementation. This should be disabled for testing purposes only.");
TAG_FLAG(use_hybrid_clock, hidden);

METRIC_DEFINE_gauge_uint64(server, hybrid_clock_timestamp,
                           "Hybrid Clock Timestamp",
                           kudu::MetricUnit::kMicroseconds,
                           "Hybrid clock timestamp.");
METRIC_DEFINE_gauge_uint64(server, hybrid_clock_error,
                           "Hybrid Clock Error",
                           kudu::MetricUnit::kMicroseconds,
                           "Server clock maximum error.");

using kudu::Status;
using strings::Substitute;

namespace kudu {
namespace server {

namespace {

// Returns the clock modes and checks if the clock is synchronized.
Status GetClockModes(timex* timex) {
  // this makes ntp_adjtime a read-only call
  timex->modes = 0;
  int rc = ntp_adjtime(timex);
  if (PREDICT_FALSE(rc == TIME_ERROR)) {
    return Status::ServiceUnavailable(
        Substitute("Error reading clock. Clock considered unsynchronized. Return code: $0", rc));
  }
  // TODO what to do about leap seconds? see KUDU-146
  if (PREDICT_FALSE(rc != TIME_OK)) {
    LOG(ERROR) << Substitute("TODO Server undergoing leap second. Return code: $0", rc);
  }
  return Status::OK();
}

// Returns the current time/max error and checks if the clock is synchronized.
kudu::Status GetClockTime(ntptimeval* timeval) {
  int rc = ntp_gettime(timeval);
  if (PREDICT_FALSE(rc == TIME_ERROR)) {
    return Status::ServiceUnavailable(
        Substitute("Error reading clock. Clock considered unsynchronized. Errno: $0",
                   ErrnoToString(errno)));
  }
  // TODO what to do about leap seconds? see KUDU-146
  if (PREDICT_FALSE(rc != TIME_OK)) {
    LOG(ERROR) << Substitute("TODO Server undergoing leap second. Return code: $0", rc);
  }
  return kudu::Status::OK();
}

Status CheckDeadlineNotWithinMicros(const MonoTime& deadline, int64_t wait_for_usec) {
  if (!deadline.Initialized()) {
    // No deadline.
    return Status::OK();
  }
  int64_t us_until_deadline = deadline.GetDeltaSince(
      MonoTime::Now(MonoTime::FINE)).ToMicroseconds();
  if (us_until_deadline <= wait_for_usec) {
    return Status::TimedOut(Substitute(
        "specified time is $0us in the future, but deadline expires in $1us",
        wait_for_usec, us_until_deadline));
  }
  return Status::OK();
}

}  // anonymous namespace

// Left shifting 12 bits gives us 12 bits for the logical value
// and should still keep accurate microseconds time until 2100+
const int HybridClock::kBitsToShift = 12;
// This mask gives us back the logical bits.
const uint64_t HybridClock::kLogicalBitMask = (1 << kBitsToShift) - 1;

const uint64_t HybridClock::kNanosPerSec = 1000000;

const double HybridClock::kAdjtimexScalingFactor = 65536;

HybridClock::HybridClock()
    : divisor_(0),
      tolerance_adjustment_(0),
      last_usec_(0),
      next_logical_(0),
      state_(kNotInitialized) {
}

Status HybridClock::Init() {
  timex timex;
  RETURN_NOT_OK(GetClockModes(&timex));

  // if the clock is synchronized but has max_error beyond max_clock_sync_error_usec
  // we still abort
  ntptimeval now;
  RETURN_NOT_OK(GetClockTime(&now));

  if (now.maxerror > FLAGS_max_clock_sync_error_usec) {
    return Status::ServiceUnavailable(Substitute("Cannot initialize HybridClock. "
        "Clock synchronized but error was too high ($0 us).", timex.maxerror));
  }

  // read whether the STA_NANO bit is set to know whether we'll get back nanos
  // or micros in timeval.time.tv_usec. See:
  // http://stackoverflow.com/questions/16063408/does-ntp-gettime-actually-return-nanosecond-precision
  // set the timeval.time.tv_usec divisor so that we always get micros
  if (timex.status & STA_NANO) {
    divisor_ = 1000;
  } else {
    divisor_ = 1;
  }

  // Calculate the sleep skew adjustment according to the max tolerance of the clock.
  // Tolerance comes in parts per million but needs to be applied a scaling factor.
  tolerance_adjustment_ = (1 + ((timex.tolerance / kAdjtimexScalingFactor) / 1000000.0));

  LOG(INFO) << "HybridClock initialized. Resolution in nanos?: " << (divisor_ == 1000)
            << " Wait times tolerance adjustment: " << tolerance_adjustment_
            << " Current error: " << now.maxerror;

  state_ = kInitialized;

  return Status::OK();
}

Timestamp HybridClock::Now() {
  Timestamp now;
  uint64_t error;

  boost::lock_guard<simple_spinlock> lock(lock_);
  NowWithError(&now, &error);
  return now;
}

Timestamp HybridClock::NowLatest() {
  Timestamp now;
  uint64_t error;

  {
    boost::lock_guard<simple_spinlock> lock(lock_);
    NowWithError(&now, &error);
  }

  uint64_t now_latest = GetPhysicalValueMicros(now) + error;
  uint64_t now_logical = GetLogicalValue(now);

  return TimestampFromMicrosecondsAndLogicalValue(now_latest, now_logical);
}

Status HybridClock::GetGlobalLatest(Timestamp* t) {
  Timestamp now = Now();
  uint64_t now_latest = GetPhysicalValueMicros(now) + FLAGS_max_clock_sync_error_usec;
  uint64_t now_logical = GetLogicalValue(now);
  *t = TimestampFromMicrosecondsAndLogicalValue(now_latest, now_logical);
  return Status::OK();
}

void HybridClock::NowWithError(Timestamp* timestamp, uint64_t* max_error_usec) {

  DCHECK_EQ(state_, kInitialized) << "Clock not initialized. Must call Init() first.";

  ntptimeval now;
  Status s = GetClockTime(&now);
  uint64_t now_usec = GetTimeUsecs(&now);
  if (PREDICT_FALSE(!s.ok())) {
    LOG(FATAL) << Substitute("Could get the current time: Clock unsynchronized. "
        "Status: $0", s.ToString());
  }
  // Test that the clock error didn't go past a pre-defined maximum error.
  if (PREDICT_FALSE(now.maxerror > FLAGS_max_clock_sync_error_usec)) {
    LOG(FATAL) << Substitute("Could get the current time: Clock synchronized, "
        "but error: $0, is past the maximum allowable error: $1",
        now.maxerror, FLAGS_max_clock_sync_error_usec);
  }

  // If the current time surpasses the last update just return it
  if (PREDICT_TRUE(now_usec > last_usec_)) {
    last_usec_ = now_usec;
    next_logical_ = 1;
    *timestamp = TimestampFromMicroseconds(last_usec_);
    *max_error_usec = now.maxerror;
    if (PREDICT_FALSE(VLOG_IS_ON(2))) {
      VLOG(2) << "Current clock is higher than the last one. Resetting logical values."
          << " Physical Value: " << now_usec << " usec Logical Value: 0  Error: "
          << now.maxerror;
    }
    return;
  }

  // We don't have the last time read max error since it might have originated
  // in another machine, but we can put a bound on the maximum error of the
  // timestamp we are providing.
  // In particular we know that the "true" time falls within the interval
  // now_usec +- now.maxerror so we get the following situations:
  //
  // 1)
  // --------|----------|----|---------|--------------------------> time
  //     now - e       now  last   now + e
  // 2)
  // --------|----------|--------------|------|-------------------> time
  //     now - e       now         now + e   last
  //
  // Assuming, in the worst case, that the "true" time is now - error we need to
  // always return: last - (now - e) as the new maximum error.
  // This broadens the error interval for both cases but always returns
  // a correct error interval.

  *max_error_usec = last_usec_ - (now_usec - now.maxerror);
  *timestamp = TimestampFromMicrosecondsAndLogicalValue(last_usec_,
                                                        next_logical_);
  if (PREDICT_FALSE(VLOG_IS_ON(2))) {
    VLOG(2) << "Current clock is lower than the last one. Returning last read and incrementing"
        " logical values. Physical Value: " << now_usec << " usec Logical Value: "
        << next_logical_ << " Error: " << *max_error_usec;
  }
  next_logical_++;
}

Status HybridClock::Update(const Timestamp& to_update) {
  boost::lock_guard<simple_spinlock> lock(lock_);
  Timestamp now;
  uint64_t error_ignored;
  NowWithError(&now, &error_ignored);

  if (PREDICT_TRUE(now.CompareTo(to_update) > 0)) return Status::OK();

  uint64_t to_update_physical = GetPhysicalValueMicros(to_update);
  uint64_t to_update_logical = GetLogicalValue(to_update);
  uint64_t now_physical = GetPhysicalValueMicros(now);

  // we won't update our clock if to_update is more than 'max_clock_sync_error_usec'
  // into the future as it might have been corrupted or originated from an out-of-sync
  // server.
  if ((to_update_physical - now_physical) > FLAGS_max_clock_sync_error_usec) {
    return Status::InvalidArgument("Tried to update clock beyond the max. error.");
  }

  last_usec_ = to_update_physical;
  next_logical_ = to_update_logical + 1;
  return Status::OK();
}

bool HybridClock::SupportsExternalConsistencyMode(ExternalConsistencyMode mode) {
  return true;
}

Status HybridClock::WaitUntilAfter(const Timestamp& then_latest,
                                   const MonoTime& deadline) {
  TRACE_EVENT0("clock", "HybridClock::WaitUntilAfter");
  Timestamp now;
  uint64_t error;
  {
    boost::lock_guard<simple_spinlock> lock(lock_);
    NowWithError(&now, &error);
  }

  // "unshift" the timestamps so that we can measure actual time
  uint64_t now_usec = GetPhysicalValueMicros(now);
  uint64_t then_latest_usec = GetPhysicalValueMicros(then_latest);

  uint64_t now_earliest_usec = now_usec - error;

  // Case 1, event happened definitely in the past, return
  if (PREDICT_TRUE(then_latest_usec < now_earliest_usec)) {
    return Status::OK();
  }

  // Case 2 wait out until we are sure that then_latest has passed

  // We'll sleep then_latest_usec - now_earliest_usec so that the new
  // nw.earliest is higher than then.latest.
  uint64_t wait_for_usec = (then_latest_usec - now_earliest_usec);

  // Additionally adjust the sleep time with the max tolerance adjustment
  // to account for the worst case clock skew while we're sleeping.
  wait_for_usec *= tolerance_adjustment_;

  // Check that sleeping wouldn't sleep longer than our deadline.
  RETURN_NOT_OK(CheckDeadlineNotWithinMicros(deadline, wait_for_usec));

  SleepFor(MonoDelta::FromMicroseconds(wait_for_usec));


  VLOG(1) << "WaitUntilAfter(): Incoming time(latest): " << then_latest_usec
          << " Now(earliest): " << now_earliest_usec << " error: " << error
          << " Waiting for: " << wait_for_usec;

  return Status::OK();
}

  Status HybridClock::WaitUntilAfterLocally(const Timestamp& then,
                                            const MonoTime& deadline) {
  while (true) {
    Timestamp now;
    uint64_t error;
    {
      boost::lock_guard<simple_spinlock> lock(lock_);
      NowWithError(&now, &error);
    }
    if (now.CompareTo(then) > 0) {
      return Status::OK();
    }
    uint64_t wait_for_usec = GetPhysicalValueMicros(then) - GetPhysicalValueMicros(now);

    // Check that sleeping wouldn't sleep longer than our deadline.
    RETURN_NOT_OK(CheckDeadlineNotWithinMicros(deadline, wait_for_usec));
  }
}

bool HybridClock::IsAfter(Timestamp t) {
  // Manually get the time, rather than using Now(), so we don't end up
  // causing a time update.
  ntptimeval now_ntp;
  CHECK_OK(GetClockTime(&now_ntp));
  uint64_t now_usec = GetTimeUsecs(&now_ntp);

  boost::lock_guard<simple_spinlock> lock(lock_);
  now_usec = std::max(now_usec, last_usec_);

  Timestamp now;
  if (now_usec > last_usec_) {
    now = TimestampFromMicroseconds(now_usec);
  } else {
    // last_usec_ may be in the future if we were updated from a remote
    // node.
    now = TimestampFromMicrosecondsAndLogicalValue(last_usec_, next_logical_);
  }

  return t.value() < now.value();
}

// Used to get the timestamp for metrics.
uint64_t HybridClock::NowForMetrics() {
  return Now().ToUint64();
}

// Used to get the current error, for metrics.
uint64_t HybridClock::ErrorForMetrics() {
  Timestamp now;
  uint64_t error;

  boost::lock_guard<simple_spinlock> lock(lock_);
  NowWithError(&now, &error);
  return error;
}

void HybridClock::RegisterMetrics(const scoped_refptr<MetricEntity>& metric_entity) {
  METRIC_hybrid_clock_timestamp.InstantiateFunctionGauge(
      metric_entity,
      Bind(&HybridClock::NowForMetrics, Unretained(this)))
    ->AutoDetachToLastValue(&metric_detacher_);
  METRIC_hybrid_clock_error.InstantiateFunctionGauge(
      metric_entity,
      Bind(&HybridClock::ErrorForMetrics, Unretained(this)))
    ->AutoDetachToLastValue(&metric_detacher_);
}

string HybridClock::Stringify(Timestamp timestamp) {
  return StringifyTimestamp(timestamp);
}

uint64_t HybridClock::GetTimeUsecs(ntptimeval* timeval) {
  return timeval->time.tv_sec * kNanosPerSec + timeval->time.tv_usec / divisor_;
}

uint64_t HybridClock::GetLogicalValue(const Timestamp& timestamp) {
  return timestamp.value() & kLogicalBitMask;
}

uint64_t HybridClock::GetPhysicalValueMicros(const Timestamp& timestamp) {
  return timestamp.value() >> kBitsToShift;
}

Timestamp HybridClock::TimestampFromMicroseconds(uint64_t micros) {
  return Timestamp(micros << kBitsToShift);
}

Timestamp HybridClock::TimestampFromMicrosecondsAndLogicalValue(
    uint64_t micros,
    uint64_t logical_value) {
  return Timestamp((micros << kBitsToShift) + logical_value);
}

Timestamp HybridClock::AddPhysicalTimeToTimestamp(const Timestamp& original,
                                                  const MonoDelta& to_add) {
  uint64_t new_physical = GetPhysicalValueMicros(original) + to_add.ToMicroseconds();
  uint64_t old_logical = GetLogicalValue(original);
  return TimestampFromMicrosecondsAndLogicalValue(new_physical, old_logical);
}

string HybridClock::StringifyTimestamp(const Timestamp& timestamp) {
  return Substitute("P: $0 usec, L: $1",
                    GetPhysicalValueMicros(timestamp),
                    GetLogicalValue(timestamp));
}


}  // namespace server
}  // namespace kudu
