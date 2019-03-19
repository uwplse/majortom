// Copyright (c) 2015, Cloudera, inc.
// Confidential Cloudera Information: Covered by NDA.

#include <string>
#include <vector>

#include <boost/foreach.hpp>
#include <gtest/gtest.h>

#include "kudu/gutil/integral_types.h"
#include "kudu/gutil/strings/substitute.h"
#include "kudu/util/jsonreader.h"
#include "kudu/util/test_macros.h"

using rapidjson::Value;
using std::string;
using std::vector;
using strings::Substitute;

namespace kudu {

TEST(JsonReaderTest, Corrupt) {
  JsonReader r("");
  Status s = r.Init();
  ASSERT_TRUE(s.IsCorruption());
  ASSERT_STR_CONTAINS(
      s.ToString(), "JSON text is corrupt: Text only contains white space(s)");
}

TEST(JsonReaderTest, Empty) {
  JsonReader r("{}");
  ASSERT_OK(r.Init());
  JsonReader r2("[]");
  ASSERT_OK(r2.Init());

  // Not found.
  ASSERT_TRUE(r.ExtractInt32(r.root(), "foo", NULL).IsNotFound());
  ASSERT_TRUE(r.ExtractInt64(r.root(), "foo", NULL).IsNotFound());
  ASSERT_TRUE(r.ExtractString(r.root(), "foo", NULL).IsNotFound());
  ASSERT_TRUE(r.ExtractObject(r.root(), "foo", NULL).IsNotFound());
  ASSERT_TRUE(r.ExtractObjectArray(r.root(), "foo", NULL).IsNotFound());
}

TEST(JsonReaderTest, Basic) {
  JsonReader r("{ \"foo\" : \"bar\" }");
  ASSERT_OK(r.Init());
  string foo;
  ASSERT_OK(r.ExtractString(r.root(), "foo", &foo));
  ASSERT_EQ("bar", foo);

  // Bad types.
  ASSERT_TRUE(r.ExtractInt32(r.root(), "foo", NULL).IsInvalidArgument());
  ASSERT_TRUE(r.ExtractInt64(r.root(), "foo", NULL).IsInvalidArgument());
  ASSERT_TRUE(r.ExtractObject(r.root(), "foo", NULL).IsInvalidArgument());
  ASSERT_TRUE(r.ExtractObjectArray(r.root(), "foo", NULL).IsInvalidArgument());
}

TEST(JsonReaderTest, LessBasic) {
  string doc = Substitute(
      "{ \"small\" : 1, \"big\" : $0, \"null\" : null, \"empty\" : \"\" }", kint64max);
  JsonReader r(doc);
  ASSERT_OK(r.Init());
  int32_t small;
  ASSERT_OK(r.ExtractInt32(r.root(), "small", &small));
  ASSERT_EQ(1, small);
  int64_t big;
  ASSERT_OK(r.ExtractInt64(r.root(), "big", &big));
  ASSERT_EQ(kint64max, big);
  string str;
  ASSERT_OK(r.ExtractString(r.root(), "null", &str));
  ASSERT_EQ("", str);
  ASSERT_OK(r.ExtractString(r.root(), "empty", &str));
  ASSERT_EQ("", str);

  // Bad types.
  ASSERT_TRUE(r.ExtractString(r.root(), "small", NULL).IsInvalidArgument());
  ASSERT_TRUE(r.ExtractObject(r.root(), "small", NULL).IsInvalidArgument());
  ASSERT_TRUE(r.ExtractObjectArray(r.root(), "small", NULL).IsInvalidArgument());

  ASSERT_TRUE(r.ExtractInt32(r.root(), "big", NULL).IsInvalidArgument());
  ASSERT_TRUE(r.ExtractString(r.root(), "big", NULL).IsInvalidArgument());
  ASSERT_TRUE(r.ExtractObject(r.root(), "big", NULL).IsInvalidArgument());
  ASSERT_TRUE(r.ExtractObjectArray(r.root(), "big", NULL).IsInvalidArgument());

  ASSERT_TRUE(r.ExtractInt32(r.root(), "null", NULL).IsInvalidArgument());
  ASSERT_TRUE(r.ExtractInt64(r.root(), "null", NULL).IsInvalidArgument());
  ASSERT_TRUE(r.ExtractObject(r.root(), "null", NULL).IsInvalidArgument());
  ASSERT_TRUE(r.ExtractObjectArray(r.root(), "null", NULL).IsInvalidArgument());

  ASSERT_TRUE(r.ExtractInt32(r.root(), "empty", NULL).IsInvalidArgument());
  ASSERT_TRUE(r.ExtractInt64(r.root(), "empty", NULL).IsInvalidArgument());
  ASSERT_TRUE(r.ExtractObject(r.root(), "empty", NULL).IsInvalidArgument());
  ASSERT_TRUE(r.ExtractObjectArray(r.root(), "empty", NULL).IsInvalidArgument());
}

TEST(JsonReaderTest, Objects) {
  JsonReader r("{ \"foo\" : { \"1\" : 1 } }");
  ASSERT_OK(r.Init());

  const Value* foo = NULL;
  ASSERT_OK(r.ExtractObject(r.root(), "foo", &foo));
  ASSERT_TRUE(foo);

  int32_t one;
  ASSERT_OK(r.ExtractInt32(foo, "1", &one));
  ASSERT_EQ(1, one);

  // Bad types.
  ASSERT_TRUE(r.ExtractInt32(r.root(), "foo", NULL).IsInvalidArgument());
  ASSERT_TRUE(r.ExtractInt64(r.root(), "foo", NULL).IsInvalidArgument());
  ASSERT_TRUE(r.ExtractString(r.root(), "foo", NULL).IsInvalidArgument());
  ASSERT_TRUE(r.ExtractObjectArray(r.root(), "foo", NULL).IsInvalidArgument());
}

TEST(JsonReaderTest, TopLevelArray) {
  JsonReader r("[ { \"name\" : \"foo\" }, { \"name\" : \"bar\" } ]");
  ASSERT_OK(r.Init());

  vector<const Value*> objs;
  ASSERT_OK(r.ExtractObjectArray(r.root(), NULL, &objs));
  ASSERT_EQ(2, objs.size());
  string name;
  ASSERT_OK(r.ExtractString(objs[0], "name", &name));
  ASSERT_EQ("foo", name);
  ASSERT_OK(r.ExtractString(objs[1], "name", &name));
  ASSERT_EQ("bar", name);

  // Bad types.
  ASSERT_TRUE(r.ExtractInt32(r.root(), NULL, NULL).IsInvalidArgument());
  ASSERT_TRUE(r.ExtractInt64(r.root(), NULL, NULL).IsInvalidArgument());
  ASSERT_TRUE(r.ExtractString(r.root(), NULL, NULL).IsInvalidArgument());
  ASSERT_TRUE(r.ExtractObject(r.root(), NULL, NULL).IsInvalidArgument());
}

TEST(JsonReaderTest, NestedArray) {
  JsonReader r("{ \"foo\" : [ { \"val\" : 0 }, { \"val\" : 1 }, { \"val\" : 2 } ] }");
  ASSERT_OK(r.Init());

  vector<const Value*> foo;
  ASSERT_OK(r.ExtractObjectArray(r.root(), "foo", &foo));
  ASSERT_EQ(3, foo.size());
  int i = 0;
  BOOST_FOREACH(const Value* v, foo) {
    int32_t number;
    ASSERT_OK(r.ExtractInt32(v, "val", &number));
    ASSERT_EQ(i, number);
    i++;
  }

  // Bad types.
  ASSERT_TRUE(r.ExtractInt32(r.root(), "foo", NULL).IsInvalidArgument());
  ASSERT_TRUE(r.ExtractInt64(r.root(), "foo", NULL).IsInvalidArgument());
  ASSERT_TRUE(r.ExtractString(r.root(), "foo", NULL).IsInvalidArgument());
  ASSERT_TRUE(r.ExtractObject(r.root(), "foo", NULL).IsInvalidArgument());
}

} // namespace kudu
