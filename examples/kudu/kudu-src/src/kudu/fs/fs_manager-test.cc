// Copyright (c) 2013, Cloudera, inc.
// Confidential Cloudera Information: Covered by NDA.

#include <boost/assign/list_of.hpp>
#include <glog/logging.h>
#include <glog/stl_logging.h>
#include <gtest/gtest.h>

#include "kudu/fs/block_manager.h"
#include "kudu/fs/fs_manager.h"
#include "kudu/gutil/strings/util.h"
#include "kudu/util/metrics.h"
#include "kudu/util/test_macros.h"
#include "kudu/util/test_util.h"

using boost::assign::list_of;
using std::tr1::shared_ptr;

namespace kudu {

class FsManagerTestBase : public KuduTest {
 public:
  void SetUp() OVERRIDE {
    KuduTest::SetUp();

    // Initialize File-System Layout
    ReinitFsManager();
    ASSERT_OK(fs_manager_->CreateInitialFileSystemLayout());
    ASSERT_OK(fs_manager_->Open());
  }

  void ReinitFsManager() {
    ReinitFsManager(GetTestPath("fs_root"),
                    list_of(GetTestPath("fs_root")));
  }

  void ReinitFsManager(const string& wal_path, const vector<string>& data_paths) {
    // Blow away the old memtrackers first.
    fs_manager_.reset();

    FsManagerOpts opts;
    opts.wal_path = wal_path;
    opts.data_paths = data_paths;
    fs_manager_.reset(new FsManager(env_.get(), opts));
  }

  void TestReadWriteDataFile(const Slice& data) {
    uint8_t buffer[64];
    DCHECK_LT(data.size(), sizeof(buffer));

    // Test Write
    gscoped_ptr<fs::WritableBlock> writer;
    ASSERT_OK(fs_manager()->CreateNewBlock(&writer));
    ASSERT_OK(writer->Append(data));
    ASSERT_OK(writer->Close());

    // Test Read
    Slice result;
    gscoped_ptr<fs::ReadableBlock> reader;
    ASSERT_OK(fs_manager()->OpenBlock(writer->id(), &reader));
    ASSERT_OK(reader->Read(0, data.size(), &result, buffer));
    ASSERT_EQ(data.size(), result.size());
    ASSERT_EQ(0, result.compare(data));
  }

  FsManager *fs_manager() const { return fs_manager_.get(); }

 private:
  gscoped_ptr<FsManager> fs_manager_;
};

TEST_F(FsManagerTestBase, TestBaseOperations) {
  fs_manager()->DumpFileSystemTree(std::cout);

  TestReadWriteDataFile(Slice("test0"));
  TestReadWriteDataFile(Slice("test1"));

  fs_manager()->DumpFileSystemTree(std::cout);
}

TEST_F(FsManagerTestBase, TestIllegalPaths) {
  vector<string> illegal = list_of("")("asdf")("/foo\n\t");
  BOOST_FOREACH(const string& path, illegal) {
    ReinitFsManager(path, list_of(path));
    ASSERT_TRUE(fs_manager()->CreateInitialFileSystemLayout().IsIOError());
  }
}

TEST_F(FsManagerTestBase, TestMultiplePaths) {
  string wal_path = GetTestPath("a");
  vector<string> data_paths = list_of(
      GetTestPath("a"))(GetTestPath("b"))(GetTestPath("c"));
  ReinitFsManager(wal_path, data_paths);
  ASSERT_OK(fs_manager()->CreateInitialFileSystemLayout());
  ASSERT_OK(fs_manager()->Open());
}

TEST_F(FsManagerTestBase, TestMatchingPathsWithMismatchedSlashes) {
  string wal_path = GetTestPath("foo");
  vector<string> data_paths = list_of(wal_path + "/");
  ReinitFsManager(wal_path, data_paths);
  ASSERT_OK(fs_manager()->CreateInitialFileSystemLayout());
}

TEST_F(FsManagerTestBase, TestDuplicatePaths) {
  string path = GetTestPath("foo");
  ReinitFsManager(path, list_of(path)(path)(path));
  ASSERT_OK(fs_manager()->CreateInitialFileSystemLayout());
  ASSERT_EQ(list_of(JoinPathSegments(path, fs_manager()->kDataDirName)),
            fs_manager()->GetDataRootDirs());
}

TEST_F(FsManagerTestBase, TestListTablets) {
  vector<string> tablet_ids;
  ASSERT_OK(fs_manager()->ListTabletIds(&tablet_ids));
  ASSERT_EQ(0, tablet_ids.size());

  string path = fs_manager()->GetTabletMetadataDir();
  gscoped_ptr<WritableFile> writer;
  ASSERT_OK(env_->NewWritableFile(
      JoinPathSegments(path, "foo.tmp"), &writer));
  ASSERT_OK(env_->NewWritableFile(
      JoinPathSegments(path, "foo.tmp.abc123"), &writer));
  ASSERT_OK(env_->NewWritableFile(
      JoinPathSegments(path, ".hidden"), &writer));
  ASSERT_OK(env_->NewWritableFile(
      JoinPathSegments(path, "a_tablet_sort_of"), &writer));

  ASSERT_OK(fs_manager()->ListTabletIds(&tablet_ids));
  ASSERT_EQ(1, tablet_ids.size()) << tablet_ids;
}

TEST_F(FsManagerTestBase, TestCannotUseNonEmptyFsRoot) {
  string path = GetTestPath("new_fs_root");
  ASSERT_OK(env_->CreateDir(path));
  {
    gscoped_ptr<WritableFile> writer;
    ASSERT_OK(env_->NewWritableFile(
        JoinPathSegments(path, "some_file"), &writer));
  }

  // Try to create the FS layout. It should fail.
  ReinitFsManager(path, list_of(path));
  ASSERT_TRUE(fs_manager()->CreateInitialFileSystemLayout().IsAlreadyPresent());
}

TEST_F(FsManagerTestBase, TestEmptyWALPath) {
  ReinitFsManager("", vector<string>());
  Status s = fs_manager()->CreateInitialFileSystemLayout();
  ASSERT_TRUE(s.IsIOError());
  ASSERT_STR_CONTAINS(s.ToString(), "directory (fs_wal_dir) not provided");
}

TEST_F(FsManagerTestBase, TestOnlyWALPath) {
  string path = GetTestPath("new_fs_root");
  ASSERT_OK(env_->CreateDir(path));

  ReinitFsManager(path, vector<string>());
  ASSERT_OK(fs_manager()->CreateInitialFileSystemLayout());
  ASSERT_TRUE(HasPrefixString(fs_manager()->GetWalsRootDir(), path));
  ASSERT_TRUE(HasPrefixString(fs_manager()->GetConsensusMetadataDir(), path));
  ASSERT_TRUE(HasPrefixString(fs_manager()->GetTabletMetadataDir(), path));
  vector<string> data_dirs = fs_manager()->GetDataRootDirs();
  ASSERT_EQ(1, data_dirs.size());
  ASSERT_TRUE(HasPrefixString(data_dirs[0], path));
}

} // namespace kudu
