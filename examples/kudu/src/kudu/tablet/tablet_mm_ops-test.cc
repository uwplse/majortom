// Copyright (c) 2015, Cloudera, inc.
// Confidential Cloudera Information: Covered by NDA.

#include "kudu/tablet/tablet.h"
#include "kudu/tablet/tablet_metrics.h"
#include "kudu/tablet/tablet_mm_ops.h"
#include "kudu/tablet/tablet-test-base.h"

using boost::assign::list_of;

namespace kudu {
namespace tablet {

class KuduTabletMmOpsTest : public TabletTestBase<IntKeyTestSetup<INT64> > {
 protected:
  typedef TabletTestBase<IntKeyTestSetup<INT64> > Superclass;

  KuduTabletMmOpsTest()
  : Superclass(),
    next_time_(MonoTime::Now(MonoTime::FINE)) {
  }

  virtual void SetUp() OVERRIDE {
    Superclass::SetUp();
    TabletMetrics* metrics = tablet()->metrics();
    all_possible_metrics_.push_back(metrics->flush_mrs_duration);
    all_possible_metrics_.push_back(metrics->flush_dms_duration);
    all_possible_metrics_.push_back(metrics->compact_rs_duration);
    all_possible_metrics_.push_back(metrics->delta_minor_compact_rs_duration);
    all_possible_metrics_.push_back(metrics->delta_major_compact_rs_duration);
  }

  // Functions that call MaintenanceOp::UpdateStats() first sleep for a nominal
  // amount of time, to ensure the "before" and "after" timestamps are unique
  // if the stats are modified.
  void StatsShouldChange(MaintenanceOp* op) {
    SleepFor(MonoDelta::FromMilliseconds(1));
    op->UpdateStats(&stats_);
    ASSERT_TRUE(next_time_.ComesBefore(stats_.last_modified()));
    next_time_ = stats_.last_modified();
  }

  void StatsShouldNotChange(MaintenanceOp* op) {
    SleepFor(MonoDelta::FromMilliseconds(1));
    op->UpdateStats(&stats_);
    ASSERT_TRUE(next_time_.Equals(stats_.last_modified()));
    next_time_ = stats_.last_modified();
  }

  void TestFirstCall(MaintenanceOp* op) {
    // The very first call to UpdateStats() will update the stats, but
    // subsequent calls are cached.
    NO_FATALS(StatsShouldChange(op));
    NO_FATALS(StatsShouldNotChange(op));
    NO_FATALS(StatsShouldNotChange(op));
  }

  void TestAffectedMetrics(MaintenanceOp* op,
                           const unordered_set<
                             scoped_refptr<Histogram>,
                             ScopedRefPtrHashFunctor<Histogram>,
                             ScopedRefPtrEqualToFunctor<Histogram> >& metrics) {
    BOOST_FOREACH(const scoped_refptr<Histogram>& c, all_possible_metrics_) {
      c->Increment(1); // value doesn't matter
      if (ContainsKey(metrics, c)) {
        NO_FATALS(StatsShouldChange(op));
      }
      NO_FATALS(StatsShouldNotChange(op));
      NO_FATALS(StatsShouldNotChange(op));
    }
  }

  MaintenanceOpStats stats_;
  MonoTime next_time_;
  vector<scoped_refptr<Histogram> > all_possible_metrics_;
};

TEST_F(KuduTabletMmOpsTest, TestCompactRowSetsOpCacheStats) {
  CompactRowSetsOp op(tablet().get());
  NO_FATALS(TestFirstCall(&op));
  NO_FATALS(TestAffectedMetrics(&op, list_of
                                (tablet()->metrics()->flush_mrs_duration)
                                (tablet()->metrics()->compact_rs_duration)));
}

TEST_F(KuduTabletMmOpsTest, TestMinorDeltaCompactionOpCacheStats) {
  MinorDeltaCompactionOp op(tablet().get());
  NO_FATALS(TestFirstCall(&op));
  NO_FATALS(TestAffectedMetrics(&op, list_of
                                (tablet()->metrics()->flush_mrs_duration)
                                (tablet()->metrics()->flush_dms_duration)
                                (tablet()->metrics()->compact_rs_duration)
                                (tablet()->metrics()->delta_minor_compact_rs_duration)));
}

TEST_F(KuduTabletMmOpsTest, TestMajorDeltaCompactionOpCacheStats) {
  MajorDeltaCompactionOp op(tablet().get());
  NO_FATALS(TestFirstCall(&op));
  NO_FATALS(TestAffectedMetrics(&op, list_of
                                (tablet()->metrics()->flush_mrs_duration)
                                (tablet()->metrics()->flush_dms_duration)
                                (tablet()->metrics()->compact_rs_duration)
                                (tablet()->metrics()->delta_minor_compact_rs_duration)
                                (tablet()->metrics()->delta_major_compact_rs_duration)));
}
} // namespace tablet
} // namespace kudu
