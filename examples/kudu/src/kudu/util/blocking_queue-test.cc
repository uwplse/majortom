// Copyright (c) 2013, Cloudera, inc.
// Confidential Cloudera Information: Covered by NDA.

#include <boost/thread/thread.hpp>
#include <glog/logging.h>
#include <gtest/gtest.h>
#include <string>
#include <tr1/memory>
#include <vector>

#include "kudu/util/countdown_latch.h"
#include "kudu/util/blocking_queue.h"

using std::tr1::shared_ptr;
using std::string;

namespace kudu {

BlockingQueue<int32_t> test1_queue(5);

void InsertSomeThings(void) {
  ASSERT_EQ(test1_queue.Put(1), QUEUE_SUCCESS);
  ASSERT_EQ(test1_queue.Put(2), QUEUE_SUCCESS);
  ASSERT_EQ(test1_queue.Put(3), QUEUE_SUCCESS);
}

TEST(BlockingQueueTest, Test1) {
  boost::thread inserter_thread(InsertSomeThings);
  int32_t i;
  ASSERT_TRUE(test1_queue.BlockingGet(&i));
  ASSERT_EQ(1, i);
  ASSERT_TRUE(test1_queue.BlockingGet(&i));
  ASSERT_EQ(2, i);
  ASSERT_TRUE(test1_queue.BlockingGet(&i));
  ASSERT_EQ(3, i);
}

TEST(BlockingQueueTest, TestBlockingDrainTo) {
  BlockingQueue<int32_t> test_queue(3);
  ASSERT_EQ(test_queue.Put(1), QUEUE_SUCCESS);
  ASSERT_EQ(test_queue.Put(2), QUEUE_SUCCESS);
  ASSERT_EQ(test_queue.Put(3), QUEUE_SUCCESS);
  std::vector<int32_t> out;
  ASSERT_TRUE(test_queue.BlockingDrainTo(&out));
  ASSERT_EQ(1, out[0]);
  ASSERT_EQ(2, out[1]);
  ASSERT_EQ(3, out[2]);
}

TEST(BlockingQueueTest, TestTooManyInsertions) {
  BlockingQueue<int32_t> test_queue(2);
  ASSERT_EQ(test_queue.Put(123), QUEUE_SUCCESS);
  ASSERT_EQ(test_queue.Put(123), QUEUE_SUCCESS);
  ASSERT_EQ(test_queue.Put(123), QUEUE_FULL);
}

namespace {

struct LengthLogicalSize {
  static size_t logical_size(const string& s) {
    return s.length();
  }
};

} // anonymous namespace

TEST(BlockingQueueTest, TestLogicalSize) {
  BlockingQueue<string, LengthLogicalSize> test_queue(4);
  ASSERT_EQ(test_queue.Put("a"), QUEUE_SUCCESS);
  ASSERT_EQ(test_queue.Put("bcd"), QUEUE_SUCCESS);
  ASSERT_EQ(test_queue.Put("e"), QUEUE_FULL);
}

TEST(BlockingQueueTest, TestNonPointerParamsMayBeNonEmptyOnDestruct) {
  BlockingQueue<int32_t> test_queue(1);
  ASSERT_EQ(test_queue.Put(123), QUEUE_SUCCESS);
  // No DCHECK failure on destruct.
}

#ifndef NDEBUG
TEST(BlockingQueueDeathTest, TestPointerParamsMustBeEmptyOnDestruct) {
  ::testing::FLAGS_gtest_death_test_style = "threadsafe";
  ASSERT_DEATH({
      BlockingQueue<int32_t*> test_queue(1);
      int32_t element = 123;
      ASSERT_EQ(test_queue.Put(&element), QUEUE_SUCCESS);
      // Debug assertion triggered on queue destruction since type is a pointer.
    },
    "BlockingQueue holds bare pointers");
}
#endif // NDEBUG

TEST(BlockingQueueTest, TestGetFromShutdownQueue) {
  BlockingQueue<int64_t> test_queue(2);
  ASSERT_EQ(test_queue.Put(123), QUEUE_SUCCESS);
  test_queue.Shutdown();
  ASSERT_EQ(test_queue.Put(456), QUEUE_SHUTDOWN);
  int64_t i;
  ASSERT_TRUE(test_queue.BlockingGet(&i));
  ASSERT_EQ(123, i);
  ASSERT_FALSE(test_queue.BlockingGet(&i));
}

TEST(BlockingQueueTest, TestGscopedPtrMethods) {
  BlockingQueue<int*> test_queue(2);
  gscoped_ptr<int> input_int(new int(123));
  ASSERT_EQ(test_queue.Put(&input_int), QUEUE_SUCCESS);
  gscoped_ptr<int> output_int;
  ASSERT_TRUE(test_queue.BlockingGet(&output_int));
  ASSERT_EQ(123, *output_int.get());
  test_queue.Shutdown();
}

class MultiThreadTest {
 public:
  typedef std::vector<std::tr1::shared_ptr<boost::thread> > thread_vec_t;

  MultiThreadTest()
   :  puts_(4),
      blocking_puts_(4),
      nthreads_(5),
      queue_(nthreads_ * puts_),
      num_inserters_(nthreads_),
      sync_latch_(nthreads_) {
  }

  void InserterThread(int arg) {
    for (int i = 0; i < puts_; i++) {
      ASSERT_EQ(queue_.Put(arg), QUEUE_SUCCESS);
    }
    sync_latch_.CountDown();
    sync_latch_.Wait();
    for (int i = 0; i < blocking_puts_; i++) {
      ASSERT_TRUE(queue_.BlockingPut(arg));
    }
    MutexLock guard(lock_);
    if (--num_inserters_ == 0) {
      queue_.Shutdown();
    }
  }

  void RemoverThread() {
    for (int i = 0; i < puts_ + blocking_puts_; i++) {
      int32_t arg = 0;
      bool got = queue_.BlockingGet(&arg);
      if (!got) {
        arg = -1;
      }
      MutexLock guard(lock_);
      gotten_[arg] = gotten_[arg] + 1;
    }
  }

  void Run() {
    for (int i = 0; i < nthreads_; i++) {
      threads_.push_back(shared_ptr<boost::thread>(
              new boost::thread(boost::bind(
                &MultiThreadTest::InserterThread, this, i))));
      threads_.push_back(shared_ptr<boost::thread>(
              new boost::thread(boost::bind(
                &MultiThreadTest::RemoverThread, this))));
    }
    // We add an extra thread to ensure that there aren't enough elements in
    // the queue to go around.  This way, we test removal after Shutdown.
    threads_.push_back(shared_ptr<boost::thread>(
            new boost::thread(boost::bind(
              &MultiThreadTest::RemoverThread, this))));
    for (thread_vec_t::iterator t = threads_.begin();
         t != threads_.end(); ++t) {
      (*t)->join();
    }
    // Let's check to make sure we got what we should have.
    MutexLock guard(lock_);
    for (int i = 0; i < nthreads_; i++) {
      ASSERT_EQ(puts_ + blocking_puts_, gotten_[i]);
    }
    // And there were nthreads_ * (puts_ + blocking_puts_)
    // elements removed, but only nthreads_ * puts_ +
    // blocking_puts_ elements added.  So some removers hit the
    // shutdown case.
    ASSERT_EQ(puts_ + blocking_puts_, gotten_[-1]);
  }

  int puts_;
  int blocking_puts_;
  int nthreads_;
  BlockingQueue<int32_t> queue_;
  Mutex lock_;
  std::map<int32_t, int> gotten_;
  thread_vec_t threads_;
  int num_inserters_;
  CountDownLatch sync_latch_;
};

TEST(BlockingQueueTest, TestMultipleThreads) {
  MultiThreadTest test;
  test.Run();
}

}  // namespace kudu
