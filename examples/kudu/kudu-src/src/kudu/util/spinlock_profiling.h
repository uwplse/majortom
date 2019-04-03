// Copyright (c) 2013, Cloudera, inc.
// Confidential Cloudera Information: Covered by NDA.
#ifndef KUDU_UTIL_SPINLOCK_PROFILING_H
#define KUDU_UTIL_SPINLOCK_PROFILING_H

#include <iosfwd>

#include "kudu/gutil/macros.h"
#include "kudu/gutil/ref_counted.h"

namespace kudu {

class MetricEntity;

// Enable instrumentation of spinlock contention.
//
// Calling this method currently does nothing, except for ensuring
// that the spinlock_profiling.cc object file gets linked into your
// executable. It needs to be somewhere reachable in your code,
// just so that gcc doesn't omit the underlying module from the binary.
void InitSpinLockContentionProfiling();

// Return the total number of microseconds spent in spinlock contention
// since the server started.
uint64_t GetSpinLockContentionMicros();

// Register metrics in the given server entity which measure the amount of
// spinlock contention.
void RegisterSpinLockContentionMetrics(const scoped_refptr<MetricEntity>& entity);

// Enable process-wide synchronization profiling.
//
// While profiling is enabled, spinlock contention will be recorded in a buffer.
// The caller should periodically call FlushSynchronizationProfile() to empty
// the buffer, or else profiles may be dropped.
void StartSynchronizationProfiling();

// Flush the current buffer of contention profile samples to the given stream.
//
// Each stack trace that has been observed results in at least one line of the
// following format:
//   <cycles> <trip count> @ <hex stack trace>
//
// Flushing the data also clears the current buffer of trace samples.
// This may be called while synchronization profiling is enabled or after it has
// been disabled.
//
// *dropped_samples will be incremented by the number of samples which were dropped
// due to the contention buffer overflowing. If profiling is enabled during this
// call, then the 'drop_count' may be slightly out-of-date with respect to the
// returned samples.
void FlushSynchronizationProfile(std::stringstream* out, int64_t* drop_count);

// Stop collecting contention profiles.
void StopSynchronizationProfiling();

} // namespace kudu
#endif /* KUDU_UTIL_SPINLOCK_PROFILING_H */
