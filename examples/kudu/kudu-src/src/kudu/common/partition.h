// Copyright (c) 2015, Cloudera, inc.
// Confidential Cloudera Information: Covered by NDA.
#ifndef KUDU_COMMON_PARTITION_H
#define KUDU_COMMON_PARTITION_H

#include <algorithm>
#include <string>
#include <vector>

#include "kudu/common/common.pb.h"
#include "kudu/common/key_encoder.h"
#include "kudu/common/partial_row.h"
#include "kudu/common/row.h"
#include "kudu/common/schema.h"
#include "kudu/gutil/ref_counted.h"
#include "kudu/util/status.h"

namespace kudu {

class ColumnRangePredicate;
class ConstContiguousRow;
class KuduPartialRow;
class PartitionSchemaPB;
class TypeInfo;

// A Partition describes the set of rows that a Tablet is responsible for
// serving. Each tablet is assigned a single Partition.
//
// Partitions consist primarily of a start and end partition key. Every row with
// a partition key that falls in a Tablet's Partition will be served by that
// tablet.
//
// In addition to the start and end partition keys, a Partition holds metadata
// to determine if a scan can prune, or skip, a partition based on the scan's
// start and end primary keys, and predicates.
class Partition {
 public:

  const std::vector<int32_t>& hash_buckets() const {
    return hash_buckets_;
  }

  Slice range_key_start() const;

  Slice range_key_end() const;

  const std::string& partition_key_start() const {
    return partition_key_start_;
  }

  const std::string& partition_key_end() const {
    return partition_key_end_;
  }

  // Serializes a partition into a protobuf message.
  void ToPB(PartitionPB* pb) const;

  // Deserializes a protobuf message into a partition.
  //
  // The protobuf message is not validated, since partitions are only expected
  // to be created by the master process.
  static void FromPB(const PartitionPB& pb, Partition* partition);

 private:
  friend class PartitionSchema;

  // Helper function for accessing the range key portion of a partition key.
  Slice range_key(const std::string& partition_key) const;

  std::vector<int32_t> hash_buckets_;

  std::string partition_key_start_;
  std::string partition_key_end_;
};

// A partition schema describes how the rows of a table are distributed among
// tablets.
//
// Primarily, a table's partition schema is responsible for translating the
// primary key column values of a row into a partition key that can be used to
// determine the tablet containing the key.
//
// The partition schema is made up of zero or more hash bucket components,
// followed by a single range component.
//
// Each hash bucket component includes one or more columns from the primary key
// column set, with the restriction that an individual primary key column may
// only be included in a single hash component.
//
// To determine the hash bucket of an individual row, the values of the columns
// of the hash component are encoded into bytes (in PK or lexicographic
// preserving encoding), then hashed into a u64, then modded into an i32. When
// constructing a partition key from a row, the buckets of the row are simply
// encoded into the partition key in order (again in PK or lexicographic
// preserving encoding).
//
// The range component contains a (possibly full or empty) subset of the primary
// key columns. When encoding the partition key, the columns of the partition
// component are encoded in order.
//
// The above is true of the relationship between rows and partition keys. It
// gets trickier with partitions (tablet partition key boundaries), because the
// boundaries of tablets do not necessarily align to rows. For instance,
// currently the absolute-start and absolute-end primary keys of a table
// represented as an empty key, but do not have a corresponding row. Partitions
// are similar, but instead of having just one absolute-start and absolute-end,
// each component of a partition schema has an absolute-start and absolute-end.
// When creating the initial set of partitions during table creation, we deal
// with this by "carrying through" absolute-start or absolute-ends into lower
// significance components.
class PartitionSchema {
 public:

  // Deserializes a protobuf message into a partition schema.
  static Status FromPB(const PartitionSchemaPB& pb,
                       const Schema& schema,
                       PartitionSchema* partition_schema) WARN_UNUSED_RESULT;

  // Serializes a partition schema into a protobuf message.
  void ToPB(PartitionSchemaPB* pb) const;

  // Appends the row's encoded partition key into the provided buffer.
  // On failure, the buffer may have data partially appended.
  Status EncodeKey(const KuduPartialRow& row, std::string* buf) const WARN_UNUSED_RESULT;

  // Appends the row's encoded partition key into the provided buffer.
  // On failure, the buffer may have data partially appended.
  Status EncodeKey(const ConstContiguousRow& row, std::string* buf) const WARN_UNUSED_RESULT;

  // Creates the set of table partitions for a partition schema and collection
  // of split rows.
  //
  // The number of resulting partitions is the product of the number of hash
  // buckets for each hash bucket component, multiplied by
  // (split_rows.size() + 1).
  Status CreatePartitions(const std::vector<KuduPartialRow>& split_rows,
                          const Schema& schema,
                          std::vector<Partition>* partitions) const WARN_UNUSED_RESULT;

  // Tests if the partition contains the row.
  Status PartitionContainsRow(const Partition& partition,
                              const KuduPartialRow& row,
                              bool* contains) const WARN_UNUSED_RESULT;

  // Tests if the partition contains the row.
  Status PartitionContainsRow(const Partition& partition,
                              const ConstContiguousRow& row,
                              bool* contains) const WARN_UNUSED_RESULT;

  // Returns a text description of the partition suitable for debug printing.
  std::string PartitionDebugString(const Partition& partition, const Schema& schema) const;

  // Returns a text description of the partial row's partition key suitable for debug printing.
  std::string RowDebugString(const KuduPartialRow& row) const;

  // Returns a text description of the row's partition key suitable for debug printing.
  std::string RowDebugString(const ConstContiguousRow& row) const;

  // Returns a text description of the encoded partition key suitable for debug printing.
  std::string PartitionKeyDebugString(const std::string& key, const Schema& schema) const;

  // Returns a text description of this partition schema suitable for debug printing.
  std::string DebugString(const Schema& schema) const;

  // Returns true if the other partition schema is equivalent to this one.
  bool Equals(const PartitionSchema& other) const;

  // Return true if the partitioning scheme simply range-partitions on the full primary key,
  // with no bucketing components, etc.
  bool IsSimplePKRangePartitioning(const Schema& schema) const;

 private:

  struct RangeSchema {
    std::vector<int32_t> column_ids;
  };

  struct HashBucketSchema {
    std::vector<int32_t> column_ids;
    int32_t num_buckets;
    uint32_t seed;
  };

  // Encodes the specified columns of a row into lexicographic sort-order
  // preserving format.
  static Status EncodeColumns(const KuduPartialRow& row,
                              const std::vector<int32_t>& column_ids,
                              std::string* buf);

  // Encodes the specified columns of a row into lexicographic sort-order
  // preserving format.
  static Status EncodeColumns(const ConstContiguousRow& row,
                              const std::vector<int32_t>& column_ids,
                              std::string* buf);

  // Returns the hash bucket of the encoded hash column. The encoded columns must match the
  // columns of the hash bucket schema.
  static int32_t BucketForEncodedColumns(const std::string& encoded_hash_columns,
                                         const HashBucketSchema& hash_bucket_schema);

  // Assigns the row to a hash bucket according to the hash schema.
  template<typename Row>
  static Status BucketForRow(const Row& row,
                             const HashBucketSchema& hash_bucket_schema,
                             int32_t* bucket);

  // Private templated helper for PartitionContainsRow.
  template<typename Row>
  Status PartitionContainsRowImpl(const Partition& partition,
                                  const Row& row,
                                  bool* contains) const;

  // Private templated helper for EncodeKey.
  template<typename Row>
  Status EncodeKeyImpl(const Row& row, string* buf) const;

  // Appends the stringified range partition components of a partial row to a
  // vector.
  //
  // If any columns of the range partition do not exist in the partial row,
  // processing stops and the provided default string piece is appended to the vector.
  void AppendRangeDebugStringComponentsOrString(const KuduPartialRow& row,
                                                StringPiece default_string,
                                                std::vector<std::string>* components) const;

  // Appends the stringified range partition components of a partial row to a
  // vector.
  //
  // If any columns of the range partition do not exist in the partial row, the
  // logical minimum value for that column will be used instead.
  void AppendRangeDebugStringComponentsOrMin(const KuduPartialRow& row,
                                             std::vector<std::string>* components) const;

  // Decodes a range partition key into a partial row, with variable-length
  // fields stored in the arena.
  Status DecodeRangeKey(Slice* encode_key,
                        KuduPartialRow* partial_row,
                        Arena* arena) const;

  // Decodes the hash bucket component of a partition key into its buckets.
  //
  // This should only be called with partition keys created from a row, not with
  // partition keys from a partition.
  Status DecodeHashBuckets(Slice* partition_key, std::vector<int32_t>* buckets) const;

  // Clears the state of this partition schema.
  void Clear();

  // Validates that this partition schema is valid. Returns OK, or an
  // appropriate error code for an invalid partition schema.
  Status Validate(const Schema& schema) const;

  std::vector<HashBucketSchema> hash_bucket_schemas_;
  RangeSchema range_schema_;
};

} // namespace kudu

#endif
