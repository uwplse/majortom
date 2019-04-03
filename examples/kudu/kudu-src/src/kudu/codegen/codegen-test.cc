// Copyright (c) 2014, Cloudera, inc.
// Confidential Cloudera Information: Covered by NDA.

#include <string>
#include <vector>

#include <boost/assign/list_of.hpp>
#include <boost/foreach.hpp>
#include <glog/logging.h>

#include "kudu/codegen/code_generator.h"
#include "kudu/codegen/row_projector.h"
#include "kudu/common/schema.h"
#include "kudu/common/row.h"
#include "kudu/common/rowblock.h"
#include "kudu/gutil/gscoped_ptr.h"
#include "kudu/gutil/ref_counted.h"
#include "kudu/util/bitmap.h"
#include "kudu/util/random.h"
#include "kudu/util/random_util.h"
#include "kudu/util/test_util.h"

using boost::assign::list_of;
using std::string;
using std::vector;

namespace kudu {

typedef RowProjector NoCodegenRP;
typedef codegen::RowProjector CodegenRP;

class CodegenTest : public KuduTest {
 public:
  CodegenTest()
    : random_(SeedRandom()),
      // Set the arena size as small as possible to catch errors during relocation,
      // for its initial size and its eventual max size.
      projections_arena_(16, kIndirectPerProjection * 2) {
    // Create the base schema.
    vector<ColumnSchema> cols = list_of
      (ColumnSchema("key           ", UINT64       ))
      (ColumnSchema("int32         ",  INT32, false))
      (ColumnSchema("int32-null-val",  INT32,  true))
      (ColumnSchema("int32-null    ",  INT32,  true))
      (ColumnSchema("str32         ", STRING, false))
      (ColumnSchema("str32-null-val", STRING,  true))
      (ColumnSchema("str32-null    ", STRING,  true));
    base_.Reset(cols, 1);
    base_ = SchemaBuilder(base_).Build(); // add IDs

    // Create an extended default schema
    cols.push_back(ColumnSchema("int32-R ",  INT32, false, kI32R,  NULL));
    cols.push_back(ColumnSchema("int32-RW",  INT32, false, kI32R, kI32W));
    cols.push_back(ColumnSchema("str32-R ", STRING, false, kStrR,  NULL));
    cols.push_back(ColumnSchema("str32-RW", STRING, false, kStrR, kStrW));
    defaults_.Reset(cols, 1);
    defaults_ = SchemaBuilder(defaults_).Build(); // add IDs

    test_rows_arena_.reset(new Arena(2 * 1024, 1024 * 1024));
    RowBuilder rb(base_);
    for (int i = 0; i < kNumTestRows; ++i) {
      rb.AddUint64(i);
      rb.AddInt32(random_.Next32());
      rb.AddInt32(random_.Next32());
      rb.AddNull();
      AddRandomString(&rb);
      AddRandomString(&rb);
      rb.AddNull();

      void* arena_data = test_rows_arena_->AllocateBytes(
        ContiguousRowHelper::row_size(base_));
      ContiguousRow dst(&base_, static_cast<uint8_t*>(arena_data));
      CHECK_OK(CopyRow(rb.row(), &dst, test_rows_arena_.get()));
      test_rows_[i].reset(new ConstContiguousRow(dst));
      rb.Reset();
    }
  }

 protected:
  Schema base_;
  Schema defaults_;

  // Compares the projection-for-read and projection-for-write results
  // of the codegen projection and the non-codegen projection
  template<bool READ>
  void TestProjection(const Schema* proj);
  // Generates a new row projector for the given projection schema.
  Status Generate(const Schema* proj, gscoped_ptr<CodegenRP>* out);

  enum {
    // Base schema column indices
    kKeyCol,
    kI32Col,
    kI32NullValCol,
    kI32NullCol,
    kStrCol,
    kStrNullValCol,
    kStrNullCol,
    // Extended default projection schema column indices
    kI32RCol,
    kI32RWCol,
    kStrRCol,
    kStrRWCol
  };

  Status CreatePartialSchema(const vector<size_t>& col_indexes,
                             Schema* out);

 private:
  // Projects the test rows into parameter rowblock using projector and
  // member projections_arena_ (should be Reset() manually).
  template<bool READ, class RowProjectorType>
  void ProjectTestRows(RowProjectorType* rp, RowBlock* rb);
  void AddRandomString(RowBuilder* rb);

  static const int kRandomStringMaxLength = 32;
  static const int kNumTestRows = 10;
  static const size_t kIndirectPerRow = 4 * kRandomStringMaxLength;
  static const size_t kIndirectPerProjection = kIndirectPerRow * kNumTestRows;
  typedef const void* DefaultValueType;
  static const DefaultValueType kI32R, kI32W, kStrR, kStrW;

  codegen::CodeGenerator generator_;
  Random random_;
  gscoped_ptr<ConstContiguousRow> test_rows_[kNumTestRows];
  Arena projections_arena_;
  gscoped_ptr<Arena> test_rows_arena_;
};

namespace {

const int32_t kI32RValue = 0xFFFF0000;
const int32_t kI32WValue = 0x0000FFFF;
const   Slice kStrRValue = "RRRRR STRING DEFAULT READ";
const   Slice kStrWValue = "WWWWW STRING DEFAULT WRITE";

// Assumes all rows are selected
// Also assumes schemas are the same.
void CheckRowBlocksEqual(const RowBlock* rb1, const RowBlock* rb2,
                         const string& name1, const string& name2) {
  CHECK_EQ(rb1->nrows(), rb2->nrows());
  const Schema& schema = rb1->schema();
  for (int i = 0; i < rb1->nrows(); ++i) {
    RowBlockRow row1 = rb1->row(i);
    RowBlockRow row2 = rb2->row(i);
    CHECK_EQ(schema.Compare(row1, row2), 0)
      << "Rows unequal (failed at row " << i << "):\n"
      << "\t(" << name1 << ") = " << schema.DebugRow(row1) << "\n"
      << "\t(" << name2 << ") = " << schema.DebugRow(row2);
  }
}

} // anonymous namespace

const CodegenTest::DefaultValueType CodegenTest::kI32R = &kI32RValue;
const CodegenTest::DefaultValueType CodegenTest::kI32W = &kI32WValue;
const CodegenTest::DefaultValueType CodegenTest::kStrR = &kStrRValue;
const CodegenTest::DefaultValueType CodegenTest::kStrW = &kStrWValue;

void CodegenTest::AddRandomString(RowBuilder* rb) {
  static char buf[kRandomStringMaxLength];
  int size = random_.Uniform(kRandomStringMaxLength);
  RandomString(buf, size, &random_);
  rb->AddString(Slice(buf, size));
}

template<bool READ, class RowProjectorType>
void CodegenTest::ProjectTestRows(RowProjectorType* rp, RowBlock* rb) {
  // Even though we can test two rows at a time, without using up the
  // extra memory for keeping an entire row block around, this tests
  // what the actual use case will be.
  for (int i = 0; i < kNumTestRows; ++i) {
    ConstContiguousRow src = *test_rows_[i];
    RowBlockRow dst = rb->row(i);
    if (READ) {
      CHECK_OK(rp->ProjectRowForRead(src, &dst, &projections_arena_));
    } else {
      CHECK_OK(rp->ProjectRowForWrite(src, &dst, &projections_arena_));
    }
  }
}

template<bool READ>
void CodegenTest::TestProjection(const Schema* proj) {
  gscoped_ptr<CodegenRP> with;
  ASSERT_OK(Generate(proj, &with));
  NoCodegenRP without(&base_, proj);
  ASSERT_OK(without.Init());

  CHECK_EQ(with->base_schema(), &base_);
  CHECK_EQ(with->projection(), proj);

  RowBlock rb_with(*proj, kNumTestRows, &projections_arena_);
  RowBlock rb_without(*proj, kNumTestRows, &projections_arena_);

  projections_arena_.Reset();
  ProjectTestRows<READ>(with.get(), &rb_with);
  ProjectTestRows<READ>(&without, &rb_without);
  CheckRowBlocksEqual(&rb_with, &rb_without, "Codegen", "Expected");
}

Status CodegenTest::Generate(const Schema* proj, gscoped_ptr<CodegenRP>* out) {
  scoped_refptr<codegen::RowProjectorFunctions> functions;
  RETURN_NOT_OK(generator_.CompileRowProjector(base_, *proj, &functions));
  out->reset(new CodegenRP(&base_, proj, functions));
  return Status::OK();
}

Status CodegenTest::CreatePartialSchema(const vector<size_t>& col_indexes,
                                        Schema* out) {
  vector<int> col_ids;
  BOOST_FOREACH(size_t col_idx, col_indexes) {
    col_ids.push_back(defaults_.column_id(col_idx));
  }
  return defaults_.CreateProjectionByIdsIgnoreMissing(col_ids, out);
}

TEST_F(CodegenTest, ObservablesTest) {
  // Test when not identity
  Schema proj = base_.CreateKeyProjection();
  gscoped_ptr<CodegenRP> with;
  CHECK_OK(Generate(&proj, &with));
  NoCodegenRP without(&base_, &proj);
  ASSERT_OK(without.Init());
  ASSERT_EQ(with->base_schema(), without.base_schema());
  ASSERT_EQ(with->projection(), without.projection());
  ASSERT_EQ(with->is_identity(), without.is_identity());
  ASSERT_FALSE(with->is_identity());

  // Test when identity
  Schema iproj = *&base_;
  gscoped_ptr<CodegenRP> iwith;
  CHECK_OK(Generate(&iproj, &iwith))
  NoCodegenRP iwithout(&base_, &iproj);
  ASSERT_OK(iwithout.Init());
  ASSERT_EQ(iwith->base_schema(), iwithout.base_schema());
  ASSERT_EQ(iwith->projection(), iwithout.projection());
  ASSERT_EQ(iwith->is_identity(), iwithout.is_identity());
  ASSERT_TRUE(iwith->is_identity());
}
// Test key projection
TEST_F(CodegenTest, TestKey) {
  Schema key = base_.CreateKeyProjection();
  TestProjection<true>(&key);
  TestProjection<false>(&key);
}

// Test int projection
TEST_F(CodegenTest, TestInts) {
  Schema ints;
  vector<size_t> part_cols = list_of<size_t>
    (kI32Col)(kI32NullValCol)(kI32NullCol);
  ASSERT_OK(CreatePartialSchema(part_cols, &ints));

  TestProjection<true>(&ints);
  TestProjection<false>(&ints);
}

// Test string projection
TEST_F(CodegenTest, TestStrings) {
  Schema strs;
  vector<size_t> part_cols = list_of<size_t>
    (kStrCol)(kStrNullValCol)(kStrNullCol);
  ASSERT_OK(CreatePartialSchema(part_cols, &strs));

  TestProjection<true>(&strs);
  TestProjection<false>(&strs);
}

// Tests the projection of every non-nullable column
TEST_F(CodegenTest, TestNonNullables) {
  Schema non_null;
  vector<size_t> part_cols = list_of<size_t>(kKeyCol)(kI32Col)(kStrCol);
  ASSERT_OK(CreatePartialSchema(part_cols, &non_null));

  TestProjection<true>(&non_null);
  TestProjection<false>(&non_null);
}

// Tests the projection of every nullable column
TEST_F(CodegenTest, TestNullables) {
  Schema nullables;
  vector<size_t> part_cols = list_of<size_t>
    (kI32NullValCol)(kI32NullCol)(kStrNullValCol)(kStrNullCol);
  ASSERT_OK(CreatePartialSchema(part_cols, &nullables));

  TestProjection<true>(&nullables);
  TestProjection<false>(&nullables);
}

// Test full schema projection
TEST_F(CodegenTest, TestFullSchema) {
  TestProjection<true>(&base_);
  TestProjection<false>(&base_);
}

// Tests just the default projection
TEST_F(CodegenTest, TestDefaultsOnly) {
  Schema pure_defaults;

  // Default read projections
  vector<size_t> part_cols = list_of<size_t>
    (kI32RCol)(kI32RWCol)(kStrRCol)(kStrRWCol);
  ASSERT_OK(CreatePartialSchema(part_cols, &pure_defaults));

  TestProjection<true>(&pure_defaults);

  // Default write projections
  part_cols = list_of<size_t>(kI32RWCol)(kStrRWCol);
  ASSERT_OK(CreatePartialSchema(part_cols, &pure_defaults));

  TestProjection<false>(&pure_defaults);
}

// Test full defaults projection
TEST_F(CodegenTest, TestFullSchemaWithDefaults) {
  TestProjection<true>(&defaults_);

  // Default write projection
  Schema full_write;
  vector<size_t> part_cols = list_of<size_t>(kKeyCol)(kI32Col)(kI32NullValCol)
    (kI32NullCol)(kStrCol)(kStrNullValCol)(kStrNullCol)(kI32RWCol)(kStrRWCol);
  ASSERT_OK(CreatePartialSchema(part_cols, &full_write));

  TestProjection<false>(&full_write);
}

} // namespace kudu
