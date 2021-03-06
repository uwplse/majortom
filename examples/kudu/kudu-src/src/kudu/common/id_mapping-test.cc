// Copyright (c) 2015, Cloudera, inc.
// Confidential Cloudera Information: Covered by NDA.

#include <gtest/gtest.h>
#include <vector>

#include "kudu/common/id_mapping.h"
#include "kudu/util/random.h"
#include "kudu/util/test_util.h"

namespace kudu {
// Basic unit test for IdMapping.
TEST(TestIdMapping, TestSimple) {
  IdMapping m;
  ASSERT_EQ(-1, m.get(1));
  m.set(1, 10);
  m.set(2, 20);
  m.set(3, 30);
  ASSERT_EQ(10, m.get(1));
  ASSERT_EQ(20, m.get(2));
  ASSERT_EQ(30, m.get(3));
}

// Insert enough entries in the mapping so that it is forced to rehash
// itself.
TEST(TestIdMapping, TestRehash) {
  IdMapping m;

  for (int i = 0; i < 1000; i++) {
    m.set(i, i * 10);
  }
  for (int i = 0; i < 1000; i++) {
    ASSERT_EQ(i * 10, m.get(i));
  }
}

// Generate a random sequence of keys.
TEST(TestIdMapping, TestRandom) {
  Random r(SeedRandom());
  IdMapping m;
  std::vector<int> picked;
  for (int i = 0; i < 1000; i++) {
    int32_t k = r.Next32();
    m.set(k, i);
    picked.push_back(k);
  }

  for (int i = 0; i < picked.size(); i++) {
    ASSERT_EQ(i, m.get(picked[i]));
  }
}

// Regression test for a particular bad sequence of inserts
// that caused a crash on a previous implementation.
//
// The particular issue here is that we have many inserts
// which have the same key modulo the initial capacity.
TEST(TestIdMapping, TestBadSequence) {
  IdMapping m;
  m.set(0, 0);
  m.set(4, 0);
  m.set(128, 0); // 0 modulo 64 and 128
  m.set(129, 0); // 1
  m.set(130, 0); // 2
  m.set(131, 0); // 3
}

} // namespace kudu
