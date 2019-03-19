// Copyright (c) 2015, Cloudera, inc.
// Confidential Cloudera Information: Covered by NDA.
#include "kudu/tools/data_gen_util.h"

#include "kudu/client/schema.h"
#include "kudu/common/partial_row.h"
#include "kudu/gutil/strings/numbers.h"
#include "kudu/util/random.h"
#include "kudu/util/status.h"

namespace kudu {
namespace tools {

void WriteValueToColumn(const client::KuduSchema& schema,
                        int col_idx,
                        uint64_t value,
                        KuduPartialRow* row) {
  client::KuduColumnSchema::DataType type = schema.Column(col_idx).type();
  char buf[kFastToBufferSize];
  switch (type) {
    case client::KuduColumnSchema::INT8:
      CHECK_OK(row->SetInt8(col_idx, value));
      break;
    case client::KuduColumnSchema::INT16:
      CHECK_OK(row->SetInt16(col_idx, value));
      break;
    case client::KuduColumnSchema::INT32:
      CHECK_OK(row->SetInt32(col_idx, value));
      break;
    case client::KuduColumnSchema::INT64:
      CHECK_OK(row->SetInt64(col_idx, value));
      break;
    case client::KuduColumnSchema::FLOAT:
      CHECK_OK(row->SetFloat(col_idx, value / 123.0));
      break;
    case client::KuduColumnSchema::DOUBLE:
      CHECK_OK(row->SetDouble(col_idx, value / 123.0));
      break;
    case client::KuduColumnSchema::STRING:
      CHECK_OK(row->SetStringCopy(col_idx, FastHex64ToBuffer(value, buf)));
      break;
    case client::KuduColumnSchema::BOOL:
      CHECK_OK(row->SetBool(col_idx, value));
      break;
    default:
      LOG(FATAL) << "Unexpected data type: " << type;
  }
}

void GenerateDataForRow(const client::KuduSchema& schema, uint64_t record_id,
                        Random* random, KuduPartialRow* row) {
  for (int col_idx = 0; col_idx < schema.num_columns(); col_idx++) {
    // We randomly generate the inserted data, except for the first column,
    // which is always based on a monotonic "record id".
    uint64_t value;
    if (col_idx == 0) {
      value = record_id;
    } else {
      value = random->Next64();
    }
    WriteValueToColumn(schema, col_idx, value, row);
  }
}

} // namespace tools
} // namespace kudu
