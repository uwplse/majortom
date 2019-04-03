// Copyright (c) 2013, Cloudera, inc.
// Confidential Cloudera Information: Covered by NDA.
// All rights reserved.

#include <boost/foreach.hpp>
#include <glog/logging.h>

#include "kudu/gutil/ref_counted.h"
#include "kudu/gutil/stringprintf.h"
#include "kudu/gutil/walltime.h"
#include "kudu/util/locks.h"
#include "kudu/util/status.h"
#include "kudu/util/test_graph.h"
#include "kudu/util/thread.h"

namespace kudu {

void TimeSeries::AddValue(double val) {
  lock_guard<simple_spinlock> l(&lock_);
  val_ += val;
}

void TimeSeries::SetValue(double val) {
  lock_guard<simple_spinlock> l(&lock_);
  val_ = val;
}

double TimeSeries::value() const {
  lock_guard<simple_spinlock> l(&lock_);
  return val_;
}

TimeSeriesCollector::~TimeSeriesCollector() {
  if (started_) {
    StopDumperThread();
  }
}

shared_ptr<TimeSeries> TimeSeriesCollector::GetTimeSeries(const string &key) {
  MutexLock l(series_lock_);
  SeriesMap::const_iterator it = series_map_.find(key);
  if (it == series_map_.end()) {
    shared_ptr<TimeSeries> ts(new TimeSeries());
    series_map_[key] = ts;
    return ts;
  } else {
    return (*it).second;
  }
}

void TimeSeriesCollector::StartDumperThread() {
  LOG(INFO) << "Starting metrics dumper";
  CHECK(!started_);
  exit_latch_.Reset(1);
  started_ = true;
  CHECK_OK(kudu::Thread::Create("time series", "dumper",
      &TimeSeriesCollector::DumperThread, this, &dumper_thread_));
}

void TimeSeriesCollector::StopDumperThread() {
  CHECK(started_);
  exit_latch_.CountDown();
  CHECK_OK(ThreadJoiner(dumper_thread_.get()).Join());
  started_ = false;
}

void TimeSeriesCollector::DumperThread() {
  CHECK(started_);
  WallTime start_time = WallTime_Now();

  faststring metrics_str;
  while (true) {
    metrics_str.clear();
    metrics_str.append("metrics: ");
    BuildMetricsString(WallTime_Now() - start_time, &metrics_str);
    LOG(INFO) << metrics_str.ToString();

    // Sleep until next dump time, or return if we should exit
    if (exit_latch_.WaitFor(MonoDelta::FromMilliseconds(250))) {
      return;
    }
  }
}

void TimeSeriesCollector::BuildMetricsString(
  WallTime time_since_start, faststring *dst_buf) const {
  MutexLock l(series_lock_);

  dst_buf->append(StringPrintf("{ \"scope\": \"%s\", \"time\": %.3f",
                               scope_.c_str(), time_since_start));

  BOOST_FOREACH(SeriesMap::const_reference entry, series_map_) {
    dst_buf->append(StringPrintf(", \"%s\": %.3f",
                                 entry.first.c_str(),  entry.second->value()));
  }
  dst_buf->append("}");
}


} // namespace kudu
