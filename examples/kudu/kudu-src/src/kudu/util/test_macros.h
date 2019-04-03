// Copyright (c) 2012, Cloudera, inc.
// Confidential Cloudera Information: Covered by NDA.
#ifndef KUDU_UTIL_TEST_MACROS_H
#define KUDU_UTIL_TEST_MACROS_H

#include <string>

// ASSERT_NO_FATAL_FAILURE is just too long to type.
#define NO_FATALS ASSERT_NO_FATAL_FAILURE

#define ASSERT_OK(status) do { \
    Status _s = status; \
    if (_s.ok()) { \
      SUCCEED(); \
    } else { \
      FAIL() << "Bad status: " << _s.ToString();  \
    } \
  } while (0);

#define EXPECT_OK(status) do { \
    Status _s = status; \
    if (_s.ok()) { \
      SUCCEED(); \
    } else { \
      ADD_FAILURE() << "Bad status: " << _s.ToString();  \
    } \
  } while (0);

// Like the above, but doesn't record successful
// tests.
#define ASSERT_OK_FAST(status) do {      \
    Status _s = status; \
    if (!_s.ok()) { \
      FAIL() << "Bad status: " << _s.ToString();  \
    } \
  } while (0);

#define ASSERT_STR_CONTAINS(str, substr) do { \
  std::string _s = (str); \
  if (_s.find((substr)) == std::string::npos) { \
    FAIL() << "Expected to find substring '" << (substr) \
    << "'. Got: '" << _s << "'"; \
  } \
  } while (0);

#define ASSERT_FILE_EXISTS(env, path) do { \
  std::string _s = path; \
  ASSERT_TRUE(env->FileExists(_s)) \
    << "Expected file to exist: " << _s; \
  } while (0);

#define ASSERT_FILE_NOT_EXISTS(env, path) do { \
  std::string _s = path; \
  ASSERT_FALSE(env->FileExists(_s)) \
    << "Expected file not to exist: " << _s; \
  } while (0);

#define CURRENT_TEST_NAME() \
  ::testing::UnitTest::GetInstance()->current_test_info()->name()

#define CURRENT_TEST_CASE_NAME() \
  ::testing::UnitTest::GetInstance()->current_test_info()->test_case_name()

#endif
