// Copyright (c) 2013, Cloudera, inc.
// Confidential Cloudera Information: Covered by NDA.

#include <gtest/gtest.h>
#include <boost/assign/list_of.hpp>

#include "kudu/common/partial_row.h"
#include "kudu/common/row.h"
#include "kudu/common/schema.h"
#include "kudu/util/test_util.h"

namespace kudu {

class PartialRowTest : public KuduTest {
 public:
  PartialRowTest()
    : schema_(boost::assign::list_of
              (ColumnSchema("key", INT32))
              (ColumnSchema("int_val", INT32))
              (ColumnSchema("string_val", STRING, true))
              (ColumnSchema("binary_val", BINARY, true)),
              1) {
    SeedRandom();
  }
 protected:
  Schema schema_;
};

TEST_F(PartialRowTest, UnitTest) {
  KuduPartialRow row(&schema_);
  string enc_key;

  // Initially all columns are unset.
  EXPECT_FALSE(row.IsColumnSet(0));
  EXPECT_FALSE(row.IsColumnSet(1));
  EXPECT_FALSE(row.IsColumnSet(2));
  EXPECT_FALSE(row.IsKeySet());
  EXPECT_EQ("", row.ToString());

  // Encoding the key when it is not set should give an error.
  EXPECT_EQ("Invalid argument: All key columns must be set: key",
            row.EncodeRowKey(&enc_key).ToString());

  // Set just the key.
  EXPECT_OK(row.SetInt32("key", 12345));
  EXPECT_TRUE(row.IsKeySet());
  EXPECT_FALSE(row.IsColumnSet(1));
  EXPECT_FALSE(row.IsColumnSet(2));
  EXPECT_EQ("int32 key=12345", row.ToString());
  int32_t x;
  EXPECT_OK(row.GetInt32("key", &x));
  EXPECT_EQ(12345, x);
  EXPECT_FALSE(row.IsNull("key"));

  // Test key encoding.
  EXPECT_EQ("OK", row.EncodeRowKey(&enc_key).ToString());
  EXPECT_EQ("\\x80\\x0009", Slice(enc_key).ToDebugString());

  // Fill in the other columns.
  EXPECT_OK(row.SetInt32("int_val", 54321));
  EXPECT_OK(row.SetStringCopy("string_val", "hello world"));
  EXPECT_TRUE(row.IsColumnSet(1));
  EXPECT_TRUE(row.IsColumnSet(2));
  EXPECT_EQ("int32 key=12345, int32 int_val=54321, string string_val=hello world",
            row.ToString());
  Slice slice;
  EXPECT_OK(row.GetString("string_val", &slice));
  EXPECT_EQ("hello world", slice.ToString());
  EXPECT_FALSE(row.IsNull("key"));

  // Set a nullable entry to NULL
  EXPECT_OK(row.SetNull("string_val"));
  EXPECT_EQ("int32 key=12345, int32 int_val=54321, string string_val=NULL",
            row.ToString());
  EXPECT_TRUE(row.IsNull("string_val"));

  // Try to set an entry with the wrong type
  Status s = row.SetStringCopy("int_val", "foo");
  EXPECT_EQ("Invalid argument: invalid type string provided for column 'int_val' (expected int32)",
            s.ToString());

  // Try to get an entry with the wrong type
  s = row.GetString("int_val", &slice);
  EXPECT_EQ("Invalid argument: invalid type string provided for column 'int_val' (expected int32)",
            s.ToString());

  // Try to set a non-nullable entry to NULL
  s = row.SetNull("key");
  EXPECT_EQ("Invalid argument: column not nullable: key[int32 NOT NULL]", s.ToString());

  // Set the NULL string back to non-NULL
  EXPECT_OK(row.SetStringCopy("string_val", "goodbye world"));
  EXPECT_EQ("int32 key=12345, int32 int_val=54321, string string_val=goodbye world",
            row.ToString());

  // Unset some columns.
  EXPECT_OK(row.Unset("string_val"));
  EXPECT_EQ("int32 key=12345, int32 int_val=54321", row.ToString());

  EXPECT_OK(row.Unset("key"));
  EXPECT_EQ("int32 int_val=54321", row.ToString());

  // Set the column by index
  EXPECT_OK(row.SetInt32(1, 99999));
  EXPECT_EQ("int32 int_val=99999", row.ToString());

  // Set the binary column as a copy.
  EXPECT_OK(row.SetBinaryCopy("binary_val", "hello_world"));
  EXPECT_EQ("int32 int_val=99999, binary binary_val=hello_world",
              row.ToString());
  // Unset the binary column.
  EXPECT_OK(row.Unset("binary_val"));
  EXPECT_EQ("int32 int_val=99999", row.ToString());

  // Even though the storage is actually the same at the moment, we shouldn't be
  // able to set string columns with SetBinary and vice versa.
  EXPECT_FALSE(row.SetBinaryCopy("string_val", "oops").ok());
  EXPECT_FALSE(row.SetStringCopy("binary_val", "oops").ok());
}

TEST_F(PartialRowTest, TestCopy) {
  KuduPartialRow row(&schema_);

  // The assignment operator is used in this test because it internally calls
  // the copy constructor.

  // Check an empty copy.
  KuduPartialRow copy = row;
  EXPECT_FALSE(copy.IsColumnSet(0));
  EXPECT_FALSE(copy.IsColumnSet(1));
  EXPECT_FALSE(copy.IsColumnSet(2));

  ASSERT_OK(row.SetInt32(0, 42));
  ASSERT_OK(row.SetInt32(1, 99));
  ASSERT_OK(row.SetStringCopy(2, "copied-string"));

  int32_t int_val;
  Slice string_val;
  Slice binary_val;

  // Check a copy with values.
  copy = row;
  ASSERT_OK(copy.GetInt32(0, &int_val));
  EXPECT_EQ(42, int_val);
  ASSERT_OK(copy.GetInt32(1, &int_val));
  EXPECT_EQ(99, int_val);
  ASSERT_OK(copy.GetString(2, &string_val));
  EXPECT_EQ("copied-string", string_val.ToString());

  // Check a copy with a null value.
  ASSERT_OK(row.SetNull(2));
  copy = row;
  EXPECT_TRUE(copy.IsNull(2));

  // Check a copy with a borrowed value.
  string borrowed_string = "borrowed-string";
  string borrowed_binary = "borrowed-binary";
  ASSERT_OK(row.SetString(2, borrowed_string));
  ASSERT_OK(row.SetBinary(3, borrowed_binary));

  copy = row;
  ASSERT_OK(copy.GetString(2, &string_val));
  EXPECT_EQ("borrowed-string", string_val.ToString());
  ASSERT_OK(copy.GetBinary(3, &binary_val));
  EXPECT_EQ("borrowed-binary", binary_val.ToString());

  borrowed_string.replace(0, 8, "mutated-");
  borrowed_binary.replace(0, 8, "mutated-");
  ASSERT_OK(copy.GetString(2, &string_val));
  EXPECT_EQ("mutated--string", string_val.ToString());
  ASSERT_OK(copy.GetBinary(3, &string_val));
  EXPECT_EQ("mutated--binary", string_val.ToString());
}

} // namespace kudu
