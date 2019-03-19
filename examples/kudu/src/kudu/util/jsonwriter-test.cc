// Copyright (c) 2014, Cloudera,inc.
// Confidential Cloudera Information: Covered by NDA.

#include <gtest/gtest.h>

#include "kudu/util/jsonwriter.h"
#include "kudu/util/jsonwriter_test.pb.h"
#include "kudu/util/test_util.h"

using jsonwriter_test::TestAllTypes;

namespace kudu {

class TestJsonWriter : public KuduTest {};

TEST_F(TestJsonWriter, TestPBEmpty) {
  TestAllTypes pb;
  ASSERT_EQ("{}", JsonWriter::ToJson(pb, JsonWriter::PRETTY));
}

TEST_F(TestJsonWriter, TestPBAllFieldTypes) {
  TestAllTypes pb;
  pb.set_optional_int32(1);
  pb.set_optional_int64(2);
  pb.set_optional_uint32(3);
  pb.set_optional_uint64(4);
  pb.set_optional_sint32(5);
  pb.set_optional_sint64(6);
  pb.set_optional_fixed32(7);
  pb.set_optional_fixed64(8);
  pb.set_optional_sfixed32(9);
  pb.set_optional_sfixed64(10);
  pb.set_optional_float(11);
  pb.set_optional_double(12);
  pb.set_optional_bool(true);
  pb.set_optional_string("hello world");
  pb.set_optional_nested_enum(TestAllTypes::FOO);
  ASSERT_EQ("{\n"
            "    \"optional_int32\": 1,\n"
            "    \"optional_int64\": 2,\n"
            "    \"optional_uint32\": 3,\n"
            "    \"optional_uint64\": 4,\n"
            "    \"optional_sint32\": 5,\n"
            "    \"optional_sint64\": 6,\n"
            "    \"optional_fixed32\": 7,\n"
            "    \"optional_fixed64\": 8,\n"
            "    \"optional_sfixed32\": 9,\n"
            "    \"optional_sfixed64\": 10,\n"
            "    \"optional_float\": 11,\n"
            "    \"optional_double\": 12,\n"
            "    \"optional_bool\": true,\n"
            "    \"optional_string\": \"hello world\",\n"
            "    \"optional_nested_enum\": \"FOO\"\n"
            "}", JsonWriter::ToJson(pb, JsonWriter::PRETTY));
  ASSERT_EQ("{"
            "\"optional_int32\":1,"
            "\"optional_int64\":2,"
            "\"optional_uint32\":3,"
            "\"optional_uint64\":4,"
            "\"optional_sint32\":5,"
            "\"optional_sint64\":6,"
            "\"optional_fixed32\":7,"
            "\"optional_fixed64\":8,"
            "\"optional_sfixed32\":9,"
            "\"optional_sfixed64\":10,"
            "\"optional_float\":11,"
            "\"optional_double\":12,"
            "\"optional_bool\":true,"
            "\"optional_string\":\"hello world\","
            "\"optional_nested_enum\":\"FOO\""
            "}", JsonWriter::ToJson(pb, JsonWriter::COMPACT));

}

TEST_F(TestJsonWriter, TestPBRepeatedPrimitives) {
  TestAllTypes pb;
  for (int i = 0; i <= 3; i++) {
    pb.add_repeated_int32(i);
  }
  ASSERT_EQ("{\n"
            "    \"repeated_int32\": [\n"
            "        0,\n"
            "        1,\n"
            "        2,\n"
            "        3\n"
            "    ]\n"
            "}", JsonWriter::ToJson(pb, JsonWriter::PRETTY));
  ASSERT_EQ("{\"repeated_int32\":[0,1,2,3]}",
            JsonWriter::ToJson(pb, JsonWriter::COMPACT));
}

TEST_F(TestJsonWriter, TestPBNestedMessage) {
  TestAllTypes pb;
  pb.add_repeated_nested_message()->set_int_field(12345);
  pb.mutable_optional_nested_message()->set_int_field(54321);
  ASSERT_EQ("{\n"
            "    \"optional_nested_message\": {\n"
            "        \"int_field\": 54321\n"
            "    },\n"
            "    \"repeated_nested_message\": [\n"
            "        {\n"
            "            \"int_field\": 12345\n"
            "        }\n"
            "    ]\n"
            "}", JsonWriter::ToJson(pb, JsonWriter::PRETTY));
  ASSERT_EQ("{\"optional_nested_message\":{\"int_field\":54321},"
            "\"repeated_nested_message\":"
            "[{\"int_field\":12345}]}",
            JsonWriter::ToJson(pb, JsonWriter::COMPACT));
}

} // namespace kudu
