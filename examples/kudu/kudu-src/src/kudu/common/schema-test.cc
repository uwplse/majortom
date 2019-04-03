// Copyright (c) 2012, Cloudera, inc.
// Confidential Cloudera Information: Covered by NDA.

#include <boost/assign/list_of.hpp>
#include <glog/logging.h>
#include <gtest/gtest.h>
#include <vector>
#include <tr1/unordered_map>

#include "kudu/common/row.h"
#include "kudu/common/schema.h"
#include "kudu/common/key_encoder.h"
#include "kudu/gutil/strings/substitute.h"
#include "kudu/util/hexdump.h"
#include "kudu/util/stopwatch.h"
#include "kudu/util/test_macros.h"

namespace kudu {
namespace tablet {

using boost::assign::list_of;
using std::vector;
using std::tr1::unordered_map;
using strings::Substitute;

// Copy a row and its referenced data into the given Arena.
static Status CopyRowToArena(const Slice &row,
                             const Schema &schema,
                             Arena *dst_arena,
                             ContiguousRow *copied) {
  Slice row_data;

  // Copy the direct row data to arena
  if (!dst_arena->RelocateSlice(row, &row_data)) {
    return Status::IOError("no space for row data in arena");
  }

  copied->Reset(row_data.mutable_data());
  RETURN_NOT_OK(RelocateIndirectDataToArena(copied, dst_arena));
  return Status::OK();
}



// Test basic functionality of Schema definition
TEST(TestSchema, TestSchema) {
  Schema empty_schema;
  ASSERT_GT(empty_schema.memory_footprint_excluding_this(), 0);

  ColumnSchema col1("key", STRING);
  ColumnSchema col2("uint32val", UINT32, true);
  ColumnSchema col3("int32val", INT32);

  vector<ColumnSchema> cols = boost::assign::list_of
    (col1)(col2)(col3);
  Schema schema(cols, 1);

  ASSERT_EQ(sizeof(Slice) + sizeof(uint32_t) + sizeof(int32_t),
            schema.byte_size());
  ASSERT_EQ(3, schema.num_columns());
  ASSERT_EQ(0, schema.column_offset(0));
  ASSERT_EQ(sizeof(Slice), schema.column_offset(1));
  ASSERT_GT(schema.memory_footprint_excluding_this(),
            empty_schema.memory_footprint_excluding_this());

  EXPECT_EQ("Schema [\n"
            "\tkey[string NOT NULL],\n"
            "\tuint32val[uint32 NULLABLE],\n"
            "\tint32val[int32 NOT NULL]\n"
            "]",
            schema.ToString());
  EXPECT_EQ("key[string NOT NULL]", schema.column(0).ToString());
  EXPECT_EQ("uint32 NULLABLE", schema.column(1).TypeToString());
}

TEST(TestSchema, TestSwap) {
  Schema schema1(boost::assign::list_of
                 (ColumnSchema("col1", STRING))
                 (ColumnSchema("col2", STRING))
                 (ColumnSchema("col3", UINT32)),
                 2);
  Schema schema2(boost::assign::list_of
                 (ColumnSchema("col3", UINT32))
                 (ColumnSchema("col2", STRING)),
                 1);
  schema1.swap(schema2);
  ASSERT_EQ(2, schema1.num_columns());
  ASSERT_EQ(1, schema1.num_key_columns());
  ASSERT_EQ(3, schema2.num_columns());
  ASSERT_EQ(2, schema2.num_key_columns());
}

TEST(TestSchema, TestReset) {
  Schema schema;
  ASSERT_FALSE(schema.initialized());

  ASSERT_OK(schema.Reset(boost::assign::list_of
                                (ColumnSchema("col3", UINT32))
                                (ColumnSchema("col2", STRING)),
                                1));
  ASSERT_TRUE(schema.initialized());

  // Swap the initialized schema with an uninitialized one.
  Schema schema2;
  schema2.swap(schema);
  ASSERT_FALSE(schema.initialized());
  ASSERT_TRUE(schema2.initialized());
}

TEST(TestSchema, TestProjectSubset) {
  Schema schema1(boost::assign::list_of
                 (ColumnSchema("col1", STRING))
                 (ColumnSchema("col2", STRING))
                 (ColumnSchema("col3", UINT32)),
                 1);

  Schema schema2(boost::assign::list_of
                 (ColumnSchema("col3", UINT32))
                 (ColumnSchema("col2", STRING)),
                 0);

  RowProjector row_projector(&schema1, &schema2);
  ASSERT_OK(row_projector.Init());

  // Verify the mapping
  ASSERT_EQ(2, row_projector.base_cols_mapping().size());
  ASSERT_EQ(0, row_projector.adapter_cols_mapping().size());
  ASSERT_EQ(0, row_projector.projection_defaults().size());

  const vector<RowProjector::ProjectionIdxMapping>& mapping = row_projector.base_cols_mapping();
  ASSERT_EQ(mapping[0].first, 0);  // col3 schema2
  ASSERT_EQ(mapping[0].second, 2); // col3 schema1
  ASSERT_EQ(mapping[1].first, 1);  // col2 schema2
  ASSERT_EQ(mapping[1].second, 1); // col2 schema1
}

// Test projection when the type of the projected column
// doesn't match the original type.
TEST(TestSchema, TestProjectTypeMismatch) {
  Schema schema1(boost::assign::list_of
                 (ColumnSchema("key", STRING))
                 (ColumnSchema("val", UINT32)),
                 1);
  Schema schema2(boost::assign::list_of
                 (ColumnSchema("val", STRING)),
                 0);

  RowProjector row_projector(&schema1, &schema2);
  Status s = row_projector.Init();
  ASSERT_TRUE(s.IsInvalidArgument());
  ASSERT_STR_CONTAINS(s.message().ToString(), "must have type");
}

// Test projection when the some columns in the projection
// are not present in the base schema
TEST(TestSchema, TestProjectMissingColumn) {
  Schema schema1(boost::assign::list_of
                 (ColumnSchema("key", STRING))
                 (ColumnSchema("val", UINT32)),
                 1);
  Schema schema2(boost::assign::list_of
                 (ColumnSchema("val", UINT32))
                 (ColumnSchema("non_present", STRING)),
                 0);
  Schema schema3(boost::assign::list_of
                 (ColumnSchema("val", UINT32))
                 (ColumnSchema("non_present", UINT32, true)),
                 0);
  uint32_t default_value = 15;
  Schema schema4(boost::assign::list_of
                 (ColumnSchema("val", UINT32))
                 (ColumnSchema("non_present", UINT32, false, &default_value)),
                 0);

  RowProjector row_projector(&schema1, &schema2);
  Status s = row_projector.Init();
  ASSERT_TRUE(s.IsInvalidArgument());
  ASSERT_STR_CONTAINS(s.message().ToString(),
    "does not exist in the projection, and it does not have a default value or a nullable type");

  // Verify Default nullable column with no default value
  ASSERT_OK(row_projector.Reset(&schema1, &schema3));

  ASSERT_EQ(1, row_projector.base_cols_mapping().size());
  ASSERT_EQ(0, row_projector.adapter_cols_mapping().size());
  ASSERT_EQ(1, row_projector.projection_defaults().size());

  ASSERT_EQ(row_projector.base_cols_mapping()[0].first, 0);  // val schema2
  ASSERT_EQ(row_projector.base_cols_mapping()[0].second, 1); // val schema1
  ASSERT_EQ(row_projector.projection_defaults()[0], 1);      // non_present schema3

  // Verify Default non nullable column with default value
  ASSERT_OK(row_projector.Reset(&schema1, &schema4));

  ASSERT_EQ(1, row_projector.base_cols_mapping().size());
  ASSERT_EQ(0, row_projector.adapter_cols_mapping().size());
  ASSERT_EQ(1, row_projector.projection_defaults().size());

  ASSERT_EQ(row_projector.base_cols_mapping()[0].first, 0);  // val schema4
  ASSERT_EQ(row_projector.base_cols_mapping()[0].second, 1); // val schema1
  ASSERT_EQ(row_projector.projection_defaults()[0], 1);      // non_present schema4
}

// Test projection mapping using IDs.
// This simulate a column rename ('val' -> 'val_renamed')
// and a new column added ('non_present')
TEST(TestSchema, TestProjectRename) {
  SchemaBuilder builder;
  ASSERT_OK(builder.AddKeyColumn("key", STRING));
  ASSERT_OK(builder.AddColumn("val", UINT32));
  Schema schema1 = builder.Build();

  builder.Reset(schema1);
  ASSERT_OK(builder.AddNullableColumn("non_present", UINT32));
  ASSERT_OK(builder.RenameColumn("val", "val_renamed"));
  Schema schema2 = builder.Build();

  RowProjector row_projector(&schema1, &schema2);
  ASSERT_OK(row_projector.Init());

  ASSERT_EQ(2, row_projector.base_cols_mapping().size());
  ASSERT_EQ(0, row_projector.adapter_cols_mapping().size());
  ASSERT_EQ(1, row_projector.projection_defaults().size());

  ASSERT_EQ(row_projector.base_cols_mapping()[0].first, 0);  // key schema2
  ASSERT_EQ(row_projector.base_cols_mapping()[0].second, 0); // key schema1

  ASSERT_EQ(row_projector.base_cols_mapping()[1].first, 1);  // val_renamed schema2
  ASSERT_EQ(row_projector.base_cols_mapping()[1].second, 1); // val schema1

  ASSERT_EQ(row_projector.projection_defaults()[0], 2);      // non_present schema2
}


// Test that the schema can be used to compare and stringify rows.
TEST(TestSchema, TestRowOperations) {
  Schema schema(boost::assign::list_of
                 (ColumnSchema("col1", STRING))
                 (ColumnSchema("col2", STRING))
                 (ColumnSchema("col3", UINT32))
                 (ColumnSchema("col4", INT32)),
                 1);

  Arena arena(1024, 256*1024);

  RowBuilder rb(schema);
  rb.AddString(string("row_a_1"));
  rb.AddString(string("row_a_2"));
  rb.AddUint32(3);
  rb.AddInt32(-3);
  ContiguousRow row_a(&schema);
  ASSERT_OK(CopyRowToArena(rb.data(), schema, &arena, &row_a));

  rb.Reset();
  rb.AddString(string("row_b_1"));
  rb.AddString(string("row_b_2"));
  rb.AddUint32(3);
  rb.AddInt32(-3);
  ContiguousRow row_b(&schema);
  ASSERT_OK(CopyRowToArena(rb.data(), schema, &arena, &row_b));

  ASSERT_GT(schema.Compare(row_b, row_a), 0);
  ASSERT_LT(schema.Compare(row_a, row_b), 0);

  ASSERT_EQ(string("(string col1=row_a_1, string col2=row_a_2, uint32 col3=3, int32 col4=-3)"),
            schema.DebugRow(row_a));
}

TEST(TestKeyEncoder, TestKeyEncoder) {
  faststring fs;
  const KeyEncoder<faststring>& encoder = GetKeyEncoder<faststring>(GetTypeInfo(STRING));

  typedef boost::tuple<vector<Slice>, Slice> test_pair;
  using boost::assign::list_of;

  vector<test_pair> pairs;

  // Simple key
  pairs.push_back(test_pair(list_of(Slice("foo", 3)),
                            Slice("foo", 3)));

  // Simple compound key
  pairs.push_back(test_pair(list_of(Slice("foo", 3))(Slice("bar", 3)),
                            Slice("foo" "\x00\x00" "bar", 8)));

  // Compound key with a \x00 in it
  pairs.push_back(test_pair(list_of(Slice("xxx\x00yyy", 7))(Slice("bar", 3)),
                            Slice("xxx" "\x00\x01" "yyy" "\x00\x00" "bar", 13)));

  int i = 0;
  BOOST_FOREACH(const test_pair &t, pairs) {
    const vector<Slice> &in = boost::get<0>(t);
    Slice expected = boost::get<1>(t);

    fs.clear();
    for (int col = 0; col < in.size(); col++) {
      encoder.Encode(&in[col], col == in.size() - 1, &fs);
    }

    ASSERT_EQ(0, expected.compare(Slice(fs)))
      << "Failed encoding example " << i << ".\n"
      << "Expected: " << HexDump(expected) << "\n"
      << "Got:      " << HexDump(Slice(fs));
    i++;
  }
}

TEST(TestSchema, TestDecodeKeys_CompoundStringKey) {
  Schema schema(boost::assign::list_of
                (ColumnSchema("col1", STRING))
                (ColumnSchema("col2", STRING))
                (ColumnSchema("col3", STRING)),
                2);

  EXPECT_EQ("(string col1=foo, string col2=bar)",
            schema.DebugEncodedRowKey(Slice("foo\0\0bar", 8), Schema::START_KEY));
  EXPECT_EQ("(string col1=fo\\000o, string col2=bar)",
            schema.DebugEncodedRowKey(Slice("fo\x00\x01o\0\0""bar", 10), Schema::START_KEY));
  EXPECT_EQ("(string col1=fo\\000o, string col2=bar\\000xy)",
            schema.DebugEncodedRowKey(Slice("fo\x00\x01o\0\0""bar\0xy", 13), Schema::START_KEY));

  EXPECT_EQ("<start of table>",
            schema.DebugEncodedRowKey("", Schema::START_KEY));
  EXPECT_EQ("<end of table>",
            schema.DebugEncodedRowKey("", Schema::END_KEY));
}

// Test that appropriate statuses are returned when trying to decode an invalid
// encoded key.
TEST(TestSchema, TestDecodeKeys_InvalidKeys) {
  Schema schema(boost::assign::list_of
                (ColumnSchema("col1", STRING))
                (ColumnSchema("col2", UINT32))
                (ColumnSchema("col3", STRING)),
                2);

  EXPECT_EQ("<invalid key: Invalid argument: Error decoding composite key component"
            " 'col1': Missing separator after composite key string component: foo>",
            schema.DebugEncodedRowKey(Slice("foo"), Schema::START_KEY));
  EXPECT_EQ("<invalid key: Invalid argument: Error decoding composite key component 'col2': "
            "key too short>",
            schema.DebugEncodedRowKey(Slice("foo\x00\x00", 5), Schema::START_KEY));
  EXPECT_EQ("<invalid key: Invalid argument: Error decoding composite key component 'col2': "
            "key too short: \\xff\\xff>",
            schema.DebugEncodedRowKey(Slice("foo\x00\x00\xff\xff", 7), Schema::START_KEY));
}

TEST(TestSchema, TestCreateProjection) {
  Schema schema(boost::assign::list_of
                (ColumnSchema("col1", STRING))
                (ColumnSchema("col2", STRING))
                (ColumnSchema("col3", STRING))
                (ColumnSchema("col4", STRING))
                (ColumnSchema("col5", STRING)),
                2);
  Schema schema_with_ids = SchemaBuilder(schema).Build();
  Schema partial_schema;

  // By names, without IDs
  ASSERT_OK(schema.CreateProjectionByNames(list_of("col1")("col2")("col4"), &partial_schema));
  EXPECT_EQ("Schema [\n"
            "\tcol1[string NOT NULL],\n"
            "\tcol2[string NOT NULL],\n"
            "\tcol4[string NOT NULL]\n"
            "]",
            partial_schema.ToString());

  // By names, with IDS
  ASSERT_OK(schema_with_ids.CreateProjectionByNames(
                list_of("col1")("col2")("col4"), &partial_schema));
  EXPECT_EQ(Substitute("Schema [\n"
                       "\t$0:col1[string NOT NULL],\n"
                       "\t$1:col2[string NOT NULL],\n"
                       "\t$2:col4[string NOT NULL]\n"
                       "]",
                       schema_with_ids.column_id(0),
                       schema_with_ids.column_id(1),
                       schema_with_ids.column_id(3)),
            partial_schema.ToString());

  // By names, with missing names.
  Status s = schema.CreateProjectionByNames(list_of("foobar"), &partial_schema);
  EXPECT_EQ("Not found: column not found: foobar", s.ToString());

  // By IDs
  ASSERT_OK(schema_with_ids.CreateProjectionByIdsIgnoreMissing(
                list_of
                (schema_with_ids.column_id(0))
                (schema_with_ids.column_id(1))
                (1000) // missing column
                (schema_with_ids.column_id(3)),
                &partial_schema));
  EXPECT_EQ(Substitute("Schema [\n"
                       "\t$0:col1[string NOT NULL],\n"
                       "\t$1:col2[string NOT NULL],\n"
                       "\t$2:col4[string NOT NULL]\n"
                       "]",
                       schema_with_ids.column_id(0),
                       schema_with_ids.column_id(1),
                       schema_with_ids.column_id(3)),
            partial_schema.ToString());
}

#ifdef NDEBUG
TEST(TestKeyEncoder, BenchmarkSimpleKey) {
  faststring fs;
  Schema schema(boost::assign::list_of
                (ColumnSchema("col1", STRING)), 1);

  RowBuilder rb(schema);
  rb.AddString(Slice("hello world"));
  ConstContiguousRow row(&rb.schema(), rb.data());

  LOG_TIMING(INFO, "Encoding") {
    for (int i = 0; i < 10000000; i++) {
      schema.EncodeComparableKey(row, &fs);
    }
  }
}
#endif

} // namespace tablet
} // namespace kudu
