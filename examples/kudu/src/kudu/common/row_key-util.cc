// Copyright (c) 2015, Cloudera, inc.
// Confidential Cloudera Information: Covered by NDA.

#include "kudu/common/row_key-util.h"

#include <boost/type_traits/is_unsigned.hpp>

#include "kudu/common/row.h"

namespace kudu {
namespace row_key_util {

namespace {

template<DataType type>
bool IncrementIntCell(void* cell_ptr) {
  typedef DataTypeTraits<type> traits;
  typedef typename traits::cpp_type cpp_type;

  cpp_type orig;
  memcpy(&orig, cell_ptr, sizeof(cpp_type));

  cpp_type inc;
  if (boost::is_unsigned<cpp_type>::value) {
    inc = orig + 1;
  } else {
    // Signed overflow is undefined in C. So, we'll use a branch here
    // instead of counting on undefined behavior.
    if (orig == MathLimits<cpp_type>::kMax) {
      inc = MathLimits<cpp_type>::kMin;
    } else {
      inc = orig + 1;
    }
  }
  memcpy(cell_ptr, &inc, sizeof(cpp_type));
  return inc > orig;
}

bool IncrementStringCell(void* cell_ptr, Arena* arena) {
  Slice orig;
  memcpy(&orig, cell_ptr, sizeof(orig));
  uint8_t* new_buf = CHECK_NOTNULL(
      static_cast<uint8_t*>(arena->AllocateBytes(orig.size() + 1)));
  memcpy(new_buf, orig.data(), orig.size());
  new_buf[orig.size()] = '\0';

  Slice inc(new_buf, orig.size() + 1);
  memcpy(cell_ptr, &inc, sizeof(inc));
  return true;
}

bool IncrementCell(const ColumnSchema& col, void* cell_ptr, Arena* arena) {
  DataType type = col.type_info()->physical_type();
  switch (type) {
#define HANDLE_TYPE(t) case t: return IncrementIntCell<t>(cell_ptr);
    HANDLE_TYPE(UINT8);
    HANDLE_TYPE(UINT16);
    HANDLE_TYPE(UINT32);
    HANDLE_TYPE(UINT64);
    HANDLE_TYPE(INT8);
    HANDLE_TYPE(INT16);
    HANDLE_TYPE(INT32);
    HANDLE_TYPE(TIMESTAMP);
    HANDLE_TYPE(INT64);
    case UNKNOWN_DATA:
    case BOOL:
    case FLOAT:
    case DOUBLE:
      LOG(FATAL) << "Unable to handle type " << type << " in row keys";
    case STRING:
    case BINARY:
      return IncrementStringCell(cell_ptr, arena);
    default: CHECK(false) << "Unknown data type: " << type;
  }
  return false; // unreachable
#undef HANDLE_TYPE
}

} // anonymous namespace

void SetKeyToMinValues(ContiguousRow* row) {
  for (int i = 0; i < row->schema()->num_key_columns(); i++) {
    const ColumnSchema& col = row->schema()->column(i);
    col.type_info()->CopyMinValue(row->mutable_cell_ptr(i));
  }
}

bool IncrementKey(ContiguousRow* row, Arena* arena) {
  return IncrementKeyPrefix(row, row->schema()->num_key_columns(), arena);
}

bool IncrementKeyPrefix(ContiguousRow* row, int prefix_len, Arena* arena) {
  for (int i = prefix_len - 1; i >= 0; --i) {
    if (IncrementCell(row->schema()->column(i),
                                row->mutable_cell_ptr(i),
                                arena)) {
      return true;
    }
  }
  return false;
}

} // namespace row_key_util
} // namespace kudu
