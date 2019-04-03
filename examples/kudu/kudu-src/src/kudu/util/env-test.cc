// Copyright (c) 2013, Cloudera, inc.
// Confidential Cloudera Information: Covered by NDA.
// All rights reserved.

#include <fcntl.h>
#include <linux/falloc.h>
#include <string>
#include <sys/types.h>
#include <tr1/memory>

#include <glog/logging.h>
#include <gtest/gtest.h>
#include <boost/assign/list_of.hpp>
#include <boost/foreach.hpp>

#include "kudu/gutil/bind.h"
#include "kudu/gutil/strings/util.h"
#include "kudu/gutil/strings/substitute.h"
#include "kudu/util/path_util.h"
#include "kudu/util/stopwatch.h"
#include "kudu/util/status.h"
#include "kudu/util/test_util.h"
#include "kudu/util/env.h"
#include "kudu/util/env_util.h"
#include "kudu/util/malloc.h"
#include "kudu/util/memenv/memenv.h"

// Copied from falloc.h. Useful for older kernels that lack support for
// hole punching; fallocate(2) will return EOPNOTSUPP.
#ifndef FALLOC_FL_KEEP_SIZE
#define FALLOC_FL_KEEP_SIZE 0x01 /* default is extend size */
#endif
#ifndef FALLOC_FL_PUNCH_HOLE
#define FALLOC_FL_PUNCH_HOLE  0x02 /* de-allocates range */
#endif

namespace kudu {

using std::string;
using std::tr1::shared_ptr;
using std::vector;

static const uint32_t kOneMb = 1024 * 1024;

class TestEnv : public KuduTest {
 public:
  virtual void SetUp() OVERRIDE {
    KuduTest::SetUp();
    CheckFallocateSupport();
  }

  // Verify that fallocate() is supported in the test directory.
  // Some local file systems like ext3 do not support it, and we don't
  // want to fail tests on those systems.
  //
  // Sets fallocate_supported_ based on the result.
  void CheckFallocateSupport() {
    static bool checked = false;
    if (checked) return;

    int fd = creat(GetTestPath("check-fallocate").c_str(), S_IWUSR);
    PCHECK(fd >= 0);
    int err = fallocate(fd, 0, 0, 4096);
    if (err != 0) {
      PCHECK(errno == ENOTSUP);
    } else {
      fallocate_supported_ = true;

      err = fallocate(fd, FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE,
                      1024, 1024);
      if (err != 0) {
        PCHECK(errno == ENOTSUP);
      } else {
        fallocate_punch_hole_supported_ = true;
      }
    }

    close(fd);

    checked = true;
  }

 protected:

  void VerifyTestData(const Slice& read_data, size_t offset) {
    for (int i = 0; i < read_data.size(); i++) {
      size_t file_offset = offset + i;
      ASSERT_EQ((file_offset * 31) & 0xff, read_data[i]) << "failed at " << i;
    }
  }

  void MakeVectors(int num_slices, int slice_size, int num_iterations,
                   gscoped_ptr<faststring[]>* data, vector<vector<Slice > >* vec) {
    data->reset(new faststring[num_iterations * num_slices]);
    vec->resize(num_iterations);

    int data_idx = 0;
    int byte_idx = 0;
    for (int vec_idx = 0; vec_idx < num_iterations; vec_idx++) {
      vector<Slice>& iter_vec = vec->at(vec_idx);
      iter_vec.resize(num_slices);
      for (int i = 0; i < num_slices; i++) {
        (*data)[data_idx].resize(slice_size);
        for (int j = 0; j < slice_size; j++) {
          (*data)[data_idx][j] = (byte_idx * 31) & 0xff;
          ++byte_idx;
        }
        iter_vec[i]= Slice((*data)[data_idx]);
        ++data_idx;
      }
    }
  }

  void ReadAndVerifyTestData(RandomAccessFile* raf, size_t offset, size_t n) {
    gscoped_ptr<uint8_t[]> scratch(new uint8_t[n]);
    Slice s;
    ASSERT_OK(env_util::ReadFully(raf, offset, n, &s,
                                         scratch.get()));
    ASSERT_EQ(n, s.size());
    ASSERT_NO_FATAL_FAILURE(VerifyTestData(s, offset));
  }

  void TestAppendVector(size_t num_slices, size_t slice_size, size_t iterations,
                        bool fast, bool pre_allocate, const WritableFileOptions& opts) {
    const string kTestPath = GetTestPath("test_env_appendvec_read_append");
    shared_ptr<WritableFile> file;
    ASSERT_OK(env_util::OpenFileForWrite(opts, env_.get(), kTestPath, &file));

    if (pre_allocate) {
      ASSERT_OK(file->PreAllocate(num_slices * slice_size * iterations));
      ASSERT_OK(file->Sync());
    }

    gscoped_ptr<faststring[]> data;
    vector<vector<Slice> > input;

    MakeVectors(num_slices, slice_size, iterations, &data, &input);

    shared_ptr<RandomAccessFile> raf;

    if (!fast) {
      ASSERT_OK(env_util::OpenFileForRandom(env_.get(), kTestPath, &raf));
    }

    srand(123);

    const string test_descr = strings::Substitute(
        "appending a vector of slices(number of slices=$0,size of slice=$1 b) $2 times",
        num_slices, slice_size, iterations);
    LOG_TIMING(INFO, test_descr)  {
      for (int i = 0; i < iterations; i++) {
        if (fast || random() % 2) {
          ASSERT_OK(file->AppendVector(input[i]));
        } else {
          BOOST_FOREACH(const Slice& slice, input[i]) {
            ASSERT_OK(file->Append(slice));
          }
        }
        if (!fast) {
          // Verify as write. Note: this requires that file is pre-allocated, otherwise
          // the ReadFully() fails with EINVAL.
          ASSERT_NO_FATAL_FAILURE(ReadAndVerifyTestData(raf.get(), num_slices * slice_size * i,
                                                        num_slices * slice_size));
        }
      }
    }

    // Verify the entire file
    ASSERT_OK(file->Close());

    if (fast) {
      ASSERT_OK(env_util::OpenFileForRandom(env_.get(), kTestPath, &raf));
    }
    for (int i = 0; i < iterations; i++) {
      ASSERT_NO_FATAL_FAILURE(ReadAndVerifyTestData(raf.get(), num_slices * slice_size * i,
                                                    num_slices * slice_size));
    }
  }

  void DoTestPreallocate(const WritableFileOptions& opts) {
    LOG(INFO) << "Testing PreAllocate() with mmap "
              << (opts.mmap_file ? "enabled" : "disabled");

    string test_path = GetTestPath("test_env_wf");
    shared_ptr<WritableFile> file;
    ASSERT_OK(env_util::OpenFileForWrite(opts, env_.get(), test_path, &file));

    // pre-allocate 1 MB
    ASSERT_OK(file->PreAllocate(kOneMb));
    ASSERT_OK(file->Sync());

    // the writable file size should report 0
    ASSERT_EQ(file->Size(), 0);
    // but the real size of the file on disk should report 1MB
    uint64_t size;
    ASSERT_OK(env_->GetFileSize(test_path, &size));
    ASSERT_EQ(size, kOneMb);

    // write 1 MB
    uint8_t scratch[kOneMb];
    Slice slice(scratch, kOneMb);
    ASSERT_OK(file->Append(slice));
    ASSERT_OK(file->Sync());

    // the writable file size should now report 1 MB
    ASSERT_EQ(file->Size(), kOneMb);
    ASSERT_OK(file->Close());
    // and the real size for the file on disk should match ony the
    // written size
    ASSERT_OK(env_->GetFileSize(test_path, &size));
    ASSERT_EQ(kOneMb, size);
  }

  void DoTestConsecutivePreallocate(const WritableFileOptions& opts) {
    LOG(INFO) << "Testing consecutive PreAllocate() with mmap "
              << (opts.mmap_file ? "enabled" : "disabled");

    string test_path = GetTestPath("test_env_wf");
    shared_ptr<WritableFile> file;
    ASSERT_OK(env_util::OpenFileForWrite(opts, env_.get(), test_path, &file));

    // pre-allocate 64 MB
    ASSERT_OK(file->PreAllocate(64 * kOneMb));
    ASSERT_OK(file->Sync());

    // the writable file size should report 0
    ASSERT_EQ(file->Size(), 0);
    // but the real size of the file on disk should report 64 MBs
    uint64_t size;
    ASSERT_OK(env_->GetFileSize(test_path, &size));
    ASSERT_EQ(size, 64 * kOneMb);

    // write 1 MB
    uint8_t scratch[kOneMb];
    Slice slice(scratch, kOneMb);
    ASSERT_OK(file->Append(slice));
    ASSERT_OK(file->Sync());

    // the writable file size should now report 1 MB
    ASSERT_EQ(kOneMb, file->Size());
    ASSERT_OK(env_->GetFileSize(test_path, &size));
    ASSERT_EQ(64 * kOneMb, size);

    // pre-allocate 64 additional MBs
    ASSERT_OK(file->PreAllocate(64 * kOneMb));
    ASSERT_OK(file->Sync());

    // the writable file size should now report 1 MB
    ASSERT_EQ(kOneMb, file->Size());
    // while the real file size should report 128 MB's
    ASSERT_OK(env_->GetFileSize(test_path, &size));
    ASSERT_EQ(128 * kOneMb, size);

    // write another MB
    ASSERT_OK(file->Append(slice));
    ASSERT_OK(file->Sync());

    // the writable file size should now report 2 MB
    ASSERT_EQ(file->Size(), 2 * kOneMb);
    // while the real file size should reamin at 128 MBs
    ASSERT_OK(env_->GetFileSize(test_path, &size));
    ASSERT_EQ(128 * kOneMb, size);

    // close the file (which ftruncates it to the real size)
    ASSERT_OK(file->Close());
    // and the real size for the file on disk should match only the written size
    ASSERT_OK(env_->GetFileSize(test_path, &size));
    ASSERT_EQ(2* kOneMb, size);
  }

  void DoTestAppendVector(const WritableFileOptions& opts) {
    LOG(INFO) << "Testing AppendVector() with mmap "
              << (opts.mmap_file ? "enabled" : "disabled");
    LOG(INFO) << "Testing AppendVector() only, NO pre-allocation";
    ASSERT_NO_FATAL_FAILURE(TestAppendVector(2000, 1024, 5, true, false, opts));

    if (!fallocate_supported_) {
      LOG(INFO) << "fallocate not supported, skipping preallocated runs";
    } else {
      LOG(INFO) << "Testing AppendVector() only, WITH pre-allocation";
      ASSERT_NO_FATAL_FAILURE(TestAppendVector(2000, 1024, 5, true, true, opts));
      LOG(INFO) << "Testing AppendVector() together with Append() and Read(), WITH pre-allocation";
      ASSERT_NO_FATAL_FAILURE(TestAppendVector(128, 4096, 5, false, true, opts));
    }
  }

  void DoTestReopen(const WritableFileOptions& opts) {
    LOG(INFO) << "Testing reopening behavior with mmap "
              << (opts.mmap_file ? "enabled" : "disabled");

    string test_path = GetTestPath("test_env_wf");
    string first = "The quick brown fox";
    string second = "jumps over the lazy dog";

    // Create the file and write to it.
    shared_ptr<WritableFile> writer;
    ASSERT_OK(env_util::OpenFileForWrite(opts,
                                         env_.get(), test_path, &writer));
    ASSERT_OK(writer->Append(first));
    ASSERT_EQ(first.length(), writer->Size());
    ASSERT_OK(writer->Close());

    // Reopen it and append to it.
    WritableFileOptions reopen_opts = opts;
    reopen_opts.mode = Env::OPEN_EXISTING;
    ASSERT_OK(env_util::OpenFileForWrite(reopen_opts,
                                         env_.get(), test_path, &writer));
    ASSERT_EQ(first.length(), writer->Size());
    ASSERT_OK(writer->Append(second));
    ASSERT_EQ(first.length() + second.length(), writer->Size());
    ASSERT_OK(writer->Close());

    // Check that the file has both strings.
    shared_ptr<RandomAccessFile> reader;
    ASSERT_OK(env_util::OpenFileForRandom(env_.get(), test_path, &reader));
    uint64_t size;
    ASSERT_OK(reader->Size(&size));
    ASSERT_EQ(first.length() + second.length(), size);
    Slice s;
    uint8_t scratch[size];
    ASSERT_OK(env_util::ReadFully(reader.get(), 0, size, &s, scratch));
    ASSERT_EQ(first + second, s.ToString());
  }

  static bool fallocate_supported_;
  static bool fallocate_punch_hole_supported_;
};

bool TestEnv::fallocate_supported_ = false;
bool TestEnv::fallocate_punch_hole_supported_ = false;

TEST_F(TestEnv, TestPreallocate) {
  if (!fallocate_supported_) {
    LOG(INFO) << "fallocate not supported, skipping test";
    return;
  }
  WritableFileOptions opts;
  opts.mmap_file = true;
  ASSERT_NO_FATAL_FAILURE(DoTestPreallocate(opts));
  opts.mmap_file = false;
  ASSERT_NO_FATAL_FAILURE(DoTestPreallocate(opts));
}

// To test consecutive pre-allocations we need higher pre-allocations since the
// mmapped regions grow in size until 2MBs (so smaller pre-allocations will easily
// be smaller than the mmapped regions size).
TEST_F(TestEnv, TestConsecutivePreallocate) {
  if (!fallocate_supported_) {
    LOG(INFO) << "fallocate not supported, skipping test";
    return;
  }
  WritableFileOptions opts;
  opts.mmap_file = true;
  ASSERT_NO_FATAL_FAILURE(DoTestConsecutivePreallocate(opts));
  opts.mmap_file = false;
  ASSERT_NO_FATAL_FAILURE(DoTestConsecutivePreallocate(opts));
}

TEST_F(TestEnv, TestHolePunch) {
  if (!fallocate_punch_hole_supported_) {
    LOG(INFO) << "hole punching not supported, skipping test";
    return;
  }
  string test_path = GetTestPath("test_env_wf");
  gscoped_ptr<RWFile> file;
  ASSERT_OK(env_->NewRWFile(test_path, &file));

  // Write 1 MB. The size and size-on-disk both agree.
  uint8_t scratch[kOneMb];
  Slice slice(scratch, kOneMb);
  ASSERT_OK(file->Write(0, slice));
  ASSERT_OK(file->Sync());
  uint64_t sz;
  ASSERT_OK(file->Size(&sz));
  ASSERT_EQ(kOneMb, sz);
  uint64_t size_on_disk;
  ASSERT_OK(env_->GetFileSizeOnDisk(test_path, &size_on_disk));
  ASSERT_EQ(kOneMb, size_on_disk);

  // Punch some data out at byte marker 4096. Now the two sizes diverge.
  uint64_t punch_amount = 4096 * 4;
  ASSERT_OK(file->PunchHole(4096, punch_amount));
  ASSERT_OK(file->Size(&sz));
  ASSERT_EQ(kOneMb, sz);
  ASSERT_OK(env_->GetFileSizeOnDisk(test_path, &size_on_disk));
  ASSERT_EQ(kOneMb - punch_amount, size_on_disk);
}

class ShortReadRandomAccessFile : public RandomAccessFile {
 public:
  explicit ShortReadRandomAccessFile(const shared_ptr<RandomAccessFile>& wrapped)
    : wrapped_(wrapped) {
  }

  virtual Status Read(uint64_t offset, size_t n, Slice* result,
                      uint8_t *scratch) const OVERRIDE {
    CHECK_GT(n, 0);
    // Divide the requested amount of data by a small integer,
    // and issue the shorter read to the underlying file.
    int short_n = n / ((rand() % 3) + 1);
    if (short_n == 0) {
      short_n = 1;
    }

    VLOG(1) << "Reading " << short_n << " instead of " << n;

    return wrapped_->Read(offset, short_n, result, scratch);
  }

  virtual Status Size(uint64_t *size) const OVERRIDE {
    return wrapped_->Size(size);
  }

  virtual const string& filename() const OVERRIDE { return wrapped_->filename(); }

  virtual size_t memory_footprint() const OVERRIDE {
    return wrapped_->memory_footprint();
  }

 private:
  const shared_ptr<RandomAccessFile> wrapped_;
};

// Write 'size' bytes of data to a file, with a simple pattern stored in it.
static void WriteTestFile(Env* env, const string& path, size_t size) {
  shared_ptr<WritableFile> wf;
  ASSERT_OK(env_util::OpenFileForWrite(env, path, &wf));
  faststring data;
  data.resize(size);
  for (int i = 0; i < data.size(); i++) {
    data[i] = (i * 31) & 0xff;
  }
  ASSERT_OK(wf->Append(Slice(data)));
  ASSERT_OK(wf->Close());
}



TEST_F(TestEnv, TestReadFully) {
  SeedRandom();
  const string kTestPath = "test";
  const int kFileSize = 64 * 1024;
  gscoped_ptr<Env> mem(NewMemEnv(Env::Default()));

  WriteTestFile(mem.get(), kTestPath, kFileSize);
  ASSERT_NO_FATAL_FAILURE();

  // Reopen for read
  shared_ptr<RandomAccessFile> raf;
  ASSERT_OK(env_util::OpenFileForRandom(mem.get(), kTestPath, &raf));

  ShortReadRandomAccessFile sr_raf(raf);

  const int kReadLength = 10000;
  Slice s;
  gscoped_ptr<uint8_t[]> scratch(new uint8_t[kReadLength]);

  // Verify that ReadFully reads the whole requested data.
  ASSERT_OK(env_util::ReadFully(&sr_raf, 0, kReadLength, &s, scratch.get()));
  ASSERT_EQ(s.data(), scratch.get()) << "Should have returned a contiguous copy";
  ASSERT_EQ(kReadLength, s.size());

  // Verify that the data read was correct.
  VerifyTestData(s, 0);

  // Verify that ReadFully fails with an IOError at EOF.
  Status status = env_util::ReadFully(&sr_raf, kFileSize - 100, 200, &s, scratch.get());
  ASSERT_FALSE(status.ok());
  ASSERT_TRUE(status.IsIOError());
  ASSERT_STR_CONTAINS(status.ToString(), "EOF");
}

TEST_F(TestEnv, TestAppendVector) {
  WritableFileOptions opts;
  opts.mmap_file = true;
  ASSERT_NO_FATAL_FAILURE(DoTestAppendVector(opts));
  opts.mmap_file = false;
  ASSERT_NO_FATAL_FAILURE(DoTestAppendVector(opts));
}

TEST_F(TestEnv, TestGetExecutablePath) {
  string p;
  ASSERT_OK(Env::Default()->GetExecutablePath(&p));
  ASSERT_TRUE(HasSuffixString(p, "env-test")) << p;
}

TEST_F(TestEnv, TestOpenEmptyRandomAccessFile) {
  Env* env = Env::Default();
  string test_file = JoinPathSegments(GetTestDataDirectory(), "test_file");
  ASSERT_NO_FATAL_FAILURE(WriteTestFile(env, test_file, 0));
  gscoped_ptr<RandomAccessFile> readable_file;
  ASSERT_OK(env->NewRandomAccessFile(test_file, &readable_file));
  uint64_t size;
  ASSERT_OK(readable_file->Size(&size));
  ASSERT_EQ(0, size);
}

TEST_F(TestEnv, TestOverwrite) {
  string test_path = GetTestPath("test_env_wf");

  // File does not exist, create it.
  shared_ptr<WritableFile> writer;
  ASSERT_OK(env_util::OpenFileForWrite(env_.get(), test_path, &writer));

  // File exists, overwrite it.
  ASSERT_OK(env_util::OpenFileForWrite(env_.get(), test_path, &writer));

  // File exists, try to overwrite (and fail).
  WritableFileOptions opts;
  opts.mode = Env::CREATE_NON_EXISTING;
  Status s = env_util::OpenFileForWrite(opts,
                                        env_.get(), test_path, &writer);
  ASSERT_TRUE(s.IsAlreadyPresent());
}

TEST_F(TestEnv, TestReopen) {
  WritableFileOptions opts;
  opts.mmap_file = true;
  ASSERT_NO_FATAL_FAILURE(DoTestReopen(opts));
  opts.mmap_file = false;
  ASSERT_NO_FATAL_FAILURE(DoTestReopen(opts));
}

TEST_F(TestEnv, TestIsDirectory) {
  string dir = GetTestPath("a_directory");
  ASSERT_OK(env_->CreateDir(dir));
  bool is_dir;
  ASSERT_OK(env_->IsDirectory(dir, &is_dir));
  ASSERT_TRUE(is_dir);

  string not_dir = GetTestPath("not_a_directory");
  gscoped_ptr<WritableFile> writer;
  ASSERT_OK(env_->NewWritableFile(not_dir, &writer));
  ASSERT_OK(env_->IsDirectory(not_dir, &is_dir));
  ASSERT_FALSE(is_dir);
}

static Status TestWalkCb(vector<string>* actual,
                         Env::FileType type,
                         const string& dirname, const string& basename) {
  VLOG(1) << type << ":" << dirname << ":" << basename;
  actual->push_back(JoinPathSegments(dirname, basename));
  return Status::OK();
}

static Status CreateDir(Env* env, const string& name, vector<string>* created) {
  RETURN_NOT_OK(env->CreateDir(name));
  created->push_back(name);
  return Status::OK();
}

static Status CreateFile(Env* env, const string& name, vector<string>* created) {
  gscoped_ptr<WritableFile> writer;
  RETURN_NOT_OK(env->NewWritableFile(name, &writer));
  created->push_back(writer->filename());
  return Status::OK();
}

TEST_F(TestEnv, TestWalk) {
  // We test with this tree:
  //
  // /root/
  // /root/file_1
  // /root/file_2
  // /root/dir_a/file_1
  // /root/dir_a/file_2
  // /root/dir_b/file_1
  // /root/dir_b/file_2
  // /root/dir_b/dir_c/file_1
  // /root/dir_b/dir_c/file_2
  string root = GetTestPath("root");
  string subdir_a = JoinPathSegments(root, "dir_a");
  string subdir_b = JoinPathSegments(root, "dir_b");
  string subdir_c = JoinPathSegments(subdir_b, "dir_c");
  string file_one = "file_1";
  string file_two = "file_2";
  vector<string> expected;
  ASSERT_OK(CreateDir(env_.get(), root, &expected));
  ASSERT_OK(CreateFile(env_.get(), JoinPathSegments(root, file_one), &expected));
  ASSERT_OK(CreateFile(env_.get(), JoinPathSegments(root, file_two), &expected));
  ASSERT_OK(CreateDir(env_.get(), subdir_a, &expected));
  ASSERT_OK(CreateFile(env_.get(), JoinPathSegments(subdir_a, file_one), &expected));
  ASSERT_OK(CreateFile(env_.get(), JoinPathSegments(subdir_a, file_two), &expected));
  ASSERT_OK(CreateDir(env_.get(), subdir_b, &expected));
  ASSERT_OK(CreateFile(env_.get(), JoinPathSegments(subdir_b, file_one), &expected));
  ASSERT_OK(CreateFile(env_.get(), JoinPathSegments(subdir_b, file_two), &expected));
  ASSERT_OK(CreateDir(env_.get(), subdir_c, &expected));
  ASSERT_OK(CreateFile(env_.get(), JoinPathSegments(subdir_c, file_one), &expected));
  ASSERT_OK(CreateFile(env_.get(), JoinPathSegments(subdir_c, file_two), &expected));

  // Do the walk.
  //
  // Sadly, tr1/unordered_set doesn't implement equality operators, so we
  // compare sorted vectors instead.
  vector<string> actual;
  ASSERT_OK(env_->Walk(root, Env::PRE_ORDER, Bind(&TestWalkCb, &actual)));
  sort(expected.begin(), expected.end());
  sort(actual.begin(), actual.end());
  ASSERT_EQ(expected, actual);
}

static Status TestWalkErrorCb(int* num_calls,
                              Env::FileType type,
                              const string& dirname, const string& basename) {
  (*num_calls)++;
  return Status::Aborted("Returning abort status");
}

TEST_F(TestEnv, TestWalkCbReturnsError) {
  string new_dir = GetTestPath("foo");
  string new_file = "myfile";
  ASSERT_OK(env_->CreateDir(new_dir));
  gscoped_ptr<WritableFile> writer;
  ASSERT_OK(env_->NewWritableFile(JoinPathSegments(new_dir, new_file), &writer));
  int num_calls = 0;
  ASSERT_TRUE(env_->Walk(new_dir, Env::PRE_ORDER,
                         Bind(&TestWalkErrorCb, &num_calls)).IsIOError());

  // Once for the directory and once for the file inside it.
  ASSERT_EQ(2, num_calls);
}

TEST_F(TestEnv, TestGetBlockSize) {
  uint64_t block_size;

  // Does not exist.
  ASSERT_TRUE(env_->GetBlockSize("does_not_exist", &block_size).IsNotFound());

  // Try with a directory.
  ASSERT_OK(env_->GetBlockSize(".", &block_size));
  ASSERT_GT(block_size, 0);

  // Try with a file.
  string path = GetTestPath("foo");
  gscoped_ptr<WritableFile> writer;
  ASSERT_OK(env_->NewWritableFile(path, &writer));
  ASSERT_OK(env_->GetBlockSize(path, &block_size));
  ASSERT_GT(block_size, 0);
}

TEST_F(TestEnv, TestRWFile) {
  // Create the file.
  gscoped_ptr<RWFile> file;
  ASSERT_OK(env_->NewRWFile(GetTestPath("foo"), &file));

  // Append to it.
  string kTestData = "abcde";
  ASSERT_OK(file->Write(0, kTestData));

  // Read from it.
  Slice result;
  gscoped_ptr<uint8_t[]> scratch(new uint8_t[kTestData.length()]);
  ASSERT_OK(file->Read(0, kTestData.length(), &result, scratch.get()));
  ASSERT_EQ(result, kTestData);
  uint64_t sz;
  ASSERT_OK(file->Size(&sz));
  ASSERT_EQ(kTestData.length(), sz);

  // Write past the end of the file and rewrite some of the interior.
  ASSERT_OK(file->Write(kTestData.length() * 2, kTestData));
  ASSERT_OK(file->Write(kTestData.length(), kTestData));
  ASSERT_OK(file->Write(1, kTestData));
  string kNewTestData = "aabcdebcdeabcde";
  gscoped_ptr<uint8_t[]> scratch2(new uint8_t[kNewTestData.length()]);
  ASSERT_OK(file->Read(0, kNewTestData.length(), &result, scratch2.get()));

  // Retest.
  ASSERT_EQ(result, kNewTestData);
  ASSERT_OK(file->Size(&sz));
  ASSERT_EQ(kNewTestData.length(), sz);

  // Make sure we can't overwrite it.
  RWFileOptions opts;
  opts.mode = Env::CREATE_NON_EXISTING;
  ASSERT_TRUE(env_->NewRWFile(opts, GetTestPath("foo"), &file).IsAlreadyPresent());

  // Reopen it without truncating the existing data.
  opts.mode = Env::OPEN_EXISTING;
  ASSERT_OK(env_->NewRWFile(opts, GetTestPath("foo"), &file));
  ASSERT_OK(file->Read(0, kNewTestData.length(), &result, scratch2.get()));
  ASSERT_EQ(result, kNewTestData);
}

TEST_F(TestEnv, TestCanonicalize) {
  vector<string> synonyms = boost::assign::list_of
      (GetTestPath("."))
      (GetTestPath("./."))
      (GetTestPath(".//./"));
  BOOST_FOREACH(const string& synonym, synonyms) {
    string result;
    ASSERT_OK(env_->Canonicalize(synonym, &result));
    ASSERT_EQ(GetTestDataDirectory(), result);
  }

  string dir = GetTestPath("some_dir");
  ASSERT_OK(env_->CreateDir(dir));
  string result;
  ASSERT_OK(env_->Canonicalize(dir + "/", &result));
  ASSERT_EQ(dir, result);

  ASSERT_TRUE(env_->Canonicalize(dir + "/bar", NULL).IsNotFound());
}

TEST_F(TestEnv, TestGetTotalRAMBytes) {
  int64_t ram = 0;
  ASSERT_OK(env_->GetTotalRAMBytes(&ram));

  // Can't test much about it.
  ASSERT_GT(ram, 0);
}

}  // namespace kudu
