// Copyright (c) 2014, Cloudera, inc.
// Confidential Cloudera Information: Covered by NDA.
#ifndef KUDU_UTIL_MUTEX_H
#define KUDU_UTIL_MUTEX_H

#include <pthread.h>
#include <glog/logging.h>
#include <sys/types.h>

#include "kudu/gutil/gscoped_ptr.h"
#include "kudu/gutil/macros.h"

namespace kudu {

class StackTrace;

// A lock built around pthread_mutex_t. Does not allow recursion.
//
// The following checks will be performed in DEBUG mode:
//   Acquire(), TryAcquire() - the lock isn't already held.
//   Release() - the lock is already held by this thread.
//
class Mutex {
 public:
  Mutex();
  ~Mutex();

  void Acquire();
  void Release();
  bool TryAcquire();

  void lock() { Acquire(); }
  void unlock() { Release(); }
  bool try_lock() { return TryAcquire(); }

#ifndef NDEBUG
  void AssertAcquired() const;
#else
  void AssertAcquired() const {}
#endif

 private:
  friend class ConditionVariable;

  pthread_mutex_t native_handle_;

#ifndef NDEBUG
  // Members and routines taking care of locks assertions.
  void CheckHeldAndUnmark();
  void CheckUnheldAndMark();

  // All private data is implicitly protected by native_handle_.
  // Be VERY careful to only access members under that lock.
  pid_t owning_tid_;
  gscoped_ptr<StackTrace> stack_trace_;
#endif

  DISALLOW_COPY_AND_ASSIGN(Mutex);
};

// A helper class that acquires the given Lock while the MutexLock is in scope.
class MutexLock {
 public:
  struct AlreadyAcquired {};

  // Acquires 'lock' (must be unheld) and wraps around it.
  //
  // Sample usage:
  // {
  //   MutexLock l(lock_); // acquired
  //   ...
  // } // released
  explicit MutexLock(Mutex& lock)
    : lock_(&lock),
      owned_(true) {
    lock_->Acquire();
  }

  // Wraps around 'lock' (must already be held by this thread).
  //
  // Sample usage:
  // {
  //   lock_.Acquire(); // acquired
  //   ...
  //   MutexLock l(lock_, AlreadyAcquired());
  //   ...
  // } // released
  MutexLock(Mutex& lock, const AlreadyAcquired&)
    : lock_(&lock),
      owned_(true) {
    lock_->AssertAcquired();
  }

  void Lock() {
    DCHECK(!owned_);
    lock_->Acquire();
    owned_ = true;
  }

  void Unlock() {
    DCHECK(owned_);
    lock_->AssertAcquired();
    lock_->Release();
    owned_ = false;
  }

  ~MutexLock() {
    if (owned_) {
      Unlock();
    }
  }

  bool OwnsLock() const {
    return owned_;
  }

 private:
  Mutex* lock_;
  bool owned_;
  DISALLOW_COPY_AND_ASSIGN(MutexLock);
};

} // namespace kudu
#endif /* KUDU_UTIL_MUTEX_H */
