// Copyright (c) 2015, Cloudera, inc.
// Confidential Cloudera Information: Covered by NDA.

#include <glog/logging.h>

#include "kudu/common/schema.h"
#include "kudu/common/wire_protocol-test-util.h"
#include "kudu/fs/fs_manager.h"
#include "kudu/gutil/ref_counted.h"
#include "kudu/tablet/local_tablet_writer.h"
#include "kudu/tablet/tablet-test-util.h"

namespace kudu {
namespace tablet {

class TestTabletMetadata : public KuduTabletTest {
 public:
  TestTabletMetadata()
      : KuduTabletTest(GetSimpleTestSchema()) {
  }

  virtual void SetUp() OVERRIDE {
    KuduTabletTest::SetUp();
    writer_.reset(new LocalTabletWriter(harness_->tablet().get(),
                                        &client_schema_));
  }

  void BuildPartialRow(int key, int intval, const char* strval,
                       gscoped_ptr<KuduPartialRow>* row);

 protected:
  gscoped_ptr<LocalTabletWriter> writer_;
};

void TestTabletMetadata::BuildPartialRow(int key, int intval, const char* strval,
                                         gscoped_ptr<KuduPartialRow>* row) {
  row->reset(new KuduPartialRow(&client_schema_));
  CHECK_OK((*row)->SetInt32(0, key));
  CHECK_OK((*row)->SetInt32(1, intval));
  CHECK_OK((*row)->SetStringCopy(2, strval));
}

// Test that loading & storing the superblock results in an equivalent file.
TEST_F(TestTabletMetadata, TestLoadFromSuperBlock) {
  // Write some data to the tablet and flush.
  gscoped_ptr<KuduPartialRow> row;
  BuildPartialRow(0, 0, "foo", &row);
  writer_->Insert(*row);
  ASSERT_OK(harness_->tablet()->Flush());

  // Create one more rowset. Write and flush.
  BuildPartialRow(1, 1, "bar", &row);
  writer_->Insert(*row);
  ASSERT_OK(harness_->tablet()->Flush());

  // Shut down the tablet.
  harness_->tablet()->Shutdown();

  TabletMetadata* meta = harness_->tablet()->metadata();

  // Dump the superblock to a PB. Save the PB to the side.
  TabletSuperBlockPB superblock_pb_1;
  ASSERT_OK(meta->ToSuperBlock(&superblock_pb_1));

  // Load the superblock PB back into the TabletMetadata.
  ASSERT_OK(meta->ReplaceSuperBlock(superblock_pb_1));

  // Dump the tablet metadata to a superblock PB again, and save it.
  TabletSuperBlockPB superblock_pb_2;
  ASSERT_OK(meta->ToSuperBlock(&superblock_pb_2));

  // Compare the 2 dumped superblock PBs.
  ASSERT_EQ(superblock_pb_1.SerializeAsString(),
            superblock_pb_2.SerializeAsString())
    << superblock_pb_1.DebugString()
    << superblock_pb_2.DebugString();

  LOG(INFO) << "Superblocks match:\n"
            << superblock_pb_1.DebugString();
}

} // namespace tablet
} // namespace kudu
