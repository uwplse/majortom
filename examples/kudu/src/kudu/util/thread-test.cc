// Copyright (c) 2013, Cloudera, inc.
// Confidential Cloudera Information: Covered by NDA.

#include "kudu/util/thread.h"

#include <gtest/gtest.h>
#include <string>

#include "kudu/gutil/ref_counted.h"
#include "kudu/util/env.h"
#include "kudu/util/test_util.h"
#include "kudu/util/thread_restrictions.h"

using std::string;

namespace kudu {

class ThreadTest : public KuduTest {};

// Join with a thread and emit warnings while waiting to join.
// This has to be manually verified.
TEST_F(ThreadTest, TestJoinAndWarn) {
  if (!AllowSlowTests()) {
    LOG(INFO) << "Skipping test in quick test mode, since this sleeps";
    return;
  }

  scoped_refptr<Thread> holder;
  ASSERT_OK(Thread::Create("test", "sleeper thread", usleep, 1000*1000, &holder));
  ASSERT_OK(ThreadJoiner(holder.get())
                   .warn_after_ms(10)
                   .warn_every_ms(100)
                   .Join());
}

TEST_F(ThreadTest, TestFailedJoin) {
  if (!AllowSlowTests()) {
    LOG(INFO) << "Skipping test in quick test mode, since this sleeps";
    return;
  }

  scoped_refptr<Thread> holder;
  ASSERT_OK(Thread::Create("test", "sleeper thread", usleep, 1000*1000, &holder));
  Status s = ThreadJoiner(holder.get())
    .give_up_after_ms(50)
    .Join();
  ASSERT_STR_CONTAINS(s.ToString(), "Timed out after 50ms joining on sleeper thread");
}

static void TryJoinOnSelf() {
  Status s = ThreadJoiner(Thread::current_thread()).Join();
  // Use CHECK instead of ASSERT because gtest isn't thread-safe.
  CHECK(s.IsInvalidArgument());
}

// Try to join on the thread that is currently running.
TEST_F(ThreadTest, TestJoinOnSelf) {
  scoped_refptr<Thread> holder;
  ASSERT_OK(Thread::Create("test", "test", TryJoinOnSelf, &holder));
  holder->Join();
  // Actual assertion is done by the thread spawned above.
}

TEST_F(ThreadTest, TestDoubleJoinIsNoOp) {
  scoped_refptr<Thread> holder;
  ASSERT_OK(Thread::Create("test", "sleeper thread", usleep, 0, &holder));
  ThreadJoiner joiner(holder.get());
  ASSERT_OK(joiner.Join());
  ASSERT_OK(joiner.Join());
}


namespace {

void ExitHandler(string* s, const char* to_append) {
  *s += to_append;
}

void CallAtExitThread(string* s) {
  Thread::current_thread()->CallAtExit(Bind(&ExitHandler, s, Unretained("hello 1, ")));
  Thread::current_thread()->CallAtExit(Bind(&ExitHandler, s, Unretained("hello 2")));
}

} // anonymous namespace

TEST_F(ThreadTest, TestCallOnExit) {
  scoped_refptr<Thread> holder;
  string s;
  ASSERT_OK(Thread::Create("test", "TestCallOnExit", CallAtExitThread, &s, &holder));
  holder->Join();
  ASSERT_EQ("hello 1, hello 2", s);
}

// The following tests only run in debug mode, since thread restrictions are no-ops
// in release builds.
#ifndef NDEBUG
TEST_F(ThreadTest, TestThreadRestrictions_IO) {
  // Default should be to allow IO
  ThreadRestrictions::AssertIOAllowed();

  ThreadRestrictions::SetIOAllowed(false);
  {
    ThreadRestrictions::ScopedAllowIO allow_io;
    ASSERT_TRUE(Env::Default()->FileExists("/"));
  }
  ThreadRestrictions::SetIOAllowed(true);

  // Disallow IO - doing IO should crash the process.
  ASSERT_DEATH({
      ThreadRestrictions::SetIOAllowed(false);
      ignore_result(Env::Default()->FileExists("/"));
    },
    "Function marked as IO-only was called from a thread that disallows IO");
}

TEST_F(ThreadTest, TestThreadRestrictions_Waiting) {
  // Default should be to allow IO
  ThreadRestrictions::AssertWaitAllowed();

  ThreadRestrictions::SetWaitAllowed(false);
  {
    ThreadRestrictions::ScopedAllowWait allow_wait;
    CountDownLatch l(0);
    l.Wait();
  }
  ThreadRestrictions::SetWaitAllowed(true);

  // Disallow waiting - blocking on a latch should crash the process.
  ASSERT_DEATH({
      ThreadRestrictions::SetWaitAllowed(false);
      CountDownLatch l(0);
      l.Wait();
    },
    "Waiting is not allowed to be used on this thread");
}
#endif // NDEBUG

} // namespace kudu
