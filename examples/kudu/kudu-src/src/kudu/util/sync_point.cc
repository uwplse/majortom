//  Copyright (c) 2014, Cloudera, inc.
// Confidential Cloudera Information: Covered by NDA.
//
//  Copyright (c) 2014, Facebook, Inc.  All rights reserved.
//  This source code is licensed under the BSD-style license found in the
//  LICENSE file in the root directory of this source tree. An additional grant
//  of patent rights can be found in the PATENTS file in the same directory.

#include "kudu/util/sync_point.h"

#include <boost/foreach.hpp>

using std::string;
using std::vector;

#ifndef NDEBUG
namespace kudu {

SyncPoint::Dependency::Dependency(const string& predecessor, const string &successor)
  : predecessor_(predecessor),
    successor_(successor) {
}

SyncPoint::SyncPoint()
  : cv_(&mutex_),
    enabled_(false) {
}

SyncPoint* SyncPoint::GetInstance() {
  static SyncPoint sync_point;
  return &sync_point;
}

void SyncPoint::LoadDependency(const vector<Dependency>& dependencies) {
  successors_.clear();
  predecessors_.clear();
  cleared_points_.clear();
  BOOST_FOREACH(const Dependency& dependency, dependencies) {
    successors_[dependency.predecessor_].push_back(dependency.successor_);
    predecessors_[dependency.successor_].push_back(dependency.predecessor_);
  }
}

bool SyncPoint::PredecessorsAllCleared(const string& point) {
  BOOST_FOREACH(const string& pred, predecessors_[point]) {
    if (cleared_points_.count(pred) == 0) {
      return false;
    }
  }
  return true;
}

void SyncPoint::EnableProcessing() {
  MutexLock lock(mutex_);
  enabled_ = true;
}

void SyncPoint::DisableProcessing() {
  MutexLock lock(mutex_);
  enabled_ = false;
}

void SyncPoint::ClearTrace() {
  MutexLock lock(mutex_);
  cleared_points_.clear();
}

void SyncPoint::Process(const string& point) {
  MutexLock lock(mutex_);

  if (!enabled_) return;

  while (!PredecessorsAllCleared(point)) {
    cv_.Wait();
  }

  cleared_points_.insert(point);
  cv_.Broadcast();
}

}  // namespace kudu
#endif  // NDEBUG
