// Copyright (c) 2014, Cloudera, inc.
// Confidential Cloudera Information: Covered by NDA.

#include "kudu/consensus/log-test-base.h"

#include <boost/thread/locks.hpp>
#include <boost/assign/list_of.hpp>
#include <boost/thread/mutex.hpp>
#include <boost/thread/thread.hpp>

#include <algorithm>
#include <vector>

#include "kudu/gutil/algorithm.h"
#include "kudu/gutil/ref_counted.h"
#include "kudu/gutil/strings/substitute.h"
#include "kudu/util/locks.h"
#include "kudu/util/random.h"
#include "kudu/util/thread.h"

DEFINE_int32(num_writer_threads, 4, "Number of threads writing to the log");
DEFINE_int32(num_batches_per_thread, 2000, "Number of batches per thread");
DEFINE_int32(num_ops_per_batch_avg, 5, "Target average number of ops per batch");

namespace kudu {
namespace log {

using std::tr1::shared_ptr;
using std::vector;
using consensus::ReplicateRefPtr;
using consensus::make_scoped_refptr_replicate;

namespace {

class CustomLatchCallback : public RefCountedThreadSafe<CustomLatchCallback> {
 public:
  CustomLatchCallback(CountDownLatch* latch, vector<Status>* errors)
      : latch_(latch),
        errors_(errors) {
  }

  void StatusCB(const Status& s) {
    if (!s.ok()) {
      errors_->push_back(s);
    }
    latch_->CountDown();
  }

  StatusCallback AsStatusCallback() {
    return Bind(&CustomLatchCallback::StatusCB, this);
  }

 private:
  CountDownLatch* latch_;
  vector<Status>* errors_;
};

} // anonymous namespace

extern const char *kTestTablet;

class MultiThreadedLogTest : public LogTestBase {
 public:
  MultiThreadedLogTest()
      : random_(SeedRandom()) {
  }

  virtual void SetUp() OVERRIDE {
    LogTestBase::SetUp();
  }

  void LogWriterThread(int thread_id) {
    CountDownLatch latch(FLAGS_num_batches_per_thread);
    vector<Status> errors;
    for (int i = 0; i < FLAGS_num_batches_per_thread; i++) {
      LogEntryBatch* entry_batch;
      vector<consensus::ReplicateRefPtr> batch_replicates;
      int num_ops = static_cast<int>(random_.Normal(
          static_cast<double>(FLAGS_num_ops_per_batch_avg), 1.0));
      DVLOG(1) << num_ops << " ops in this batch";
      num_ops =  std::max(num_ops, 1);
      {
        boost::lock_guard<simple_spinlock> lock_guard(lock_);
        for (int j = 0; j < num_ops; j++) {
          ReplicateRefPtr replicate = make_scoped_refptr_replicate(new ReplicateMsg);
          int32_t index = current_index_++;
          OpId* op_id = replicate->get()->mutable_id();
          op_id->set_term(0);
          op_id->set_index(index);

          replicate->get()->set_op_type(WRITE_OP);
          replicate->get()->set_timestamp(clock_->Now().ToUint64());

          tserver::WriteRequestPB* request = replicate->get()->mutable_write_request();
          AddTestRowToPB(RowOperationsPB::INSERT, schema_, index, 0,
                         "this is a test insert",
                         request->mutable_row_operations());
          request->set_tablet_id(kTestTablet);
          batch_replicates.push_back(replicate);
        }

        gscoped_ptr<log::LogEntryBatchPB> entry_batch_pb;
        CreateBatchFromAllocatedOperations(batch_replicates,
                                           &entry_batch_pb);

        ASSERT_OK(log_->Reserve(REPLICATE, entry_batch_pb.Pass(), &entry_batch));
      } // lock_guard scope
      CustomLatchCallback* cb = new CustomLatchCallback(&latch, &errors);
      entry_batch->SetReplicates(batch_replicates);
      ASSERT_OK(log_->AsyncAppend(entry_batch, cb->AsStatusCallback()));
    }
    LOG_TIMING(INFO, strings::Substitute("thread $0 waiting to append and sync $1 batches",
                                        thread_id, FLAGS_num_batches_per_thread)) {
      latch.Wait();
    }
    BOOST_FOREACH(const Status& status, errors) {
      WARN_NOT_OK(status, "Unexpected failure during AsyncAppend");
    }
    ASSERT_EQ(0, errors.size());
  }

  void Run() {
    for (int i = 0; i < FLAGS_num_writer_threads; i++) {
      scoped_refptr<kudu::Thread> new_thread;
      CHECK_OK(kudu::Thread::Create("test", "inserter",
          &MultiThreadedLogTest::LogWriterThread, this, i, &new_thread));
      threads_.push_back(new_thread);
    }
    BOOST_FOREACH(scoped_refptr<kudu::Thread>& thread, threads_) {
      ASSERT_OK(ThreadJoiner(thread.get()).Join());
    }
  }
 private:
  ThreadSafeRandom random_;
  simple_spinlock lock_;
  vector<scoped_refptr<kudu::Thread> > threads_;
};

TEST_F(MultiThreadedLogTest, TestAppends) {
  BuildLog();
  int start_current_id = current_index_;
  LOG_TIMING(INFO, strings::Substitute("inserting $0 batches($1 threads, $2 per-thread)",
                                      FLAGS_num_writer_threads * FLAGS_num_batches_per_thread,
                                      FLAGS_num_batches_per_thread, FLAGS_num_writer_threads)) {
    ASSERT_NO_FATAL_FAILURE(Run());
  }
  ASSERT_OK(log_->Close());

  SegmentSequence segments;
  ASSERT_OK(log_->GetLogReader()->GetSegmentsSnapshot(&segments));

  BOOST_FOREACH(const SegmentSequence::value_type& entry, segments) {
    ASSERT_OK(entry->ReadEntries(&entries_));
  }
  vector<uint32_t> ids;
  EntriesToIdList(&ids);
  DVLOG(1) << "Wrote total of " << current_index_ - start_current_id << " ops";
  ASSERT_EQ(current_index_ - start_current_id, ids.size());
  ASSERT_TRUE(util::gtl::is_sorted(ids.begin(), ids.end()));
}

} // namespace log
} // namespace kudu
