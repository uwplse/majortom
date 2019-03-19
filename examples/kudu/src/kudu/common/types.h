// Copyright (c) 2012, Cloudera, inc.
// Confidential Cloudera Information: Covered by NDA.

#ifndef KUDU_COMMON_TYPES_H
#define KUDU_COMMON_TYPES_H

#include <glog/logging.h>

#include <stdint.h>
#include <string>
#include <string.h>
#include "kudu/common/common.pb.h"
#include "kudu/gutil/mathlimits.h"
#include "kudu/gutil/strings/escaping.h"
#include "kudu/gutil/strings/numbers.h"
#include "kudu/util/slice.h"

namespace kudu {

// The size of the in-memory format of the largest
// type we support.
const int kLargestTypeSize = sizeof(Slice);

using std::string;
class TypeInfo;

// This is the important bit of this header:
// given a type enum, get the TypeInfo about it.
extern const TypeInfo* GetTypeInfo(DataType type);

// Information about a given type.
// This is a runtime equivalent of the TypeTraits template below.
class TypeInfo {
 public:
  // Returns the type mentioned in the schema.
  DataType type() const { return type_; }
  // Returns the type used to actually store the data.
  DataType physical_type() const { return physical_type_; }
  const string& name() const { return name_; }
  const size_t size() const { return size_; }
  void AppendDebugStringForValue(const void *ptr, string *str) const;
  int Compare(const void *lhs, const void *rhs) const;
  void CopyMinValue(void* dst) const {
    memcpy(dst, min_value_, size_);
  }

 private:
  friend class TypeInfoResolver;
  template<typename Type> TypeInfo(Type t);

  const DataType type_;
  const DataType physical_type_;
  const string name_;
  const size_t size_;
  const void* const min_value_;

  typedef void (*AppendDebugFunc)(const void *, string *);
  const AppendDebugFunc append_func_;

  typedef int (*CompareFunc)(const void *, const void *);
  const CompareFunc compare_func_;
};

template<DataType Type> struct DataTypeTraits {};

template<DataType Type>
static int GenericCompare(const void *lhs, const void *rhs) {
  typedef typename DataTypeTraits<Type>::cpp_type CppType;
  CppType lhs_int = *reinterpret_cast<const CppType *>(lhs);
  CppType rhs_int = *reinterpret_cast<const CppType *>(rhs);
  if (lhs_int < rhs_int) {
    return -1;
  } else if (lhs_int > rhs_int) {
    return 1;
  } else {
    return 0;
  }
}

template<>
struct DataTypeTraits<UINT8> {
  static const DataType physical_type = UINT8;
  typedef uint8_t cpp_type;
  static const char *name() {
    return "uint8";
  }
  static void AppendDebugStringForValue(const void *val, string *str) {
    str->append(SimpleItoa(*reinterpret_cast<const uint8_t *>(val)));
  }
  static int Compare(const void *lhs, const void *rhs) {
    return GenericCompare<UINT8>(lhs, rhs);
  }
  static const cpp_type* min_value() {
    return &MathLimits<cpp_type>::kMin;
  }
};

template<>
struct DataTypeTraits<INT8> {
  static const DataType physical_type = INT8;
  typedef int8_t cpp_type;
  static const char *name() {
    return "int8";
  }
  static void AppendDebugStringForValue(const void *val, string *str) {
    str->append(SimpleItoa(*reinterpret_cast<const int8_t *>(val)));
  }
  static int Compare(const void *lhs, const void *rhs) {
    return GenericCompare<INT8>(lhs, rhs);
  }
  static const cpp_type* min_value() {
    return &MathLimits<cpp_type>::kMin;
  }
};

template<>
struct DataTypeTraits<UINT16> {
  static const DataType physical_type = UINT16;
  typedef uint16_t cpp_type;
  static const char *name() {
    return "uint16";
  }
  static void AppendDebugStringForValue(const void *val, string *str) {
    str->append(SimpleItoa(*reinterpret_cast<const uint16_t *>(val)));
  }
  static int Compare(const void *lhs, const void *rhs) {
    return GenericCompare<UINT16>(lhs, rhs);
  }
  static const cpp_type* min_value() {
    return &MathLimits<cpp_type>::kMin;
  }
};

template<>
struct DataTypeTraits<INT16> {
  static const DataType physical_type = INT16;
  typedef int16_t cpp_type;
  static const char *name() {
    return "int16";
  }
  static void AppendDebugStringForValue(const void *val, string *str) {
    str->append(SimpleItoa(*reinterpret_cast<const int16_t *>(val)));
  }
  static int Compare(const void *lhs, const void *rhs) {
    return GenericCompare<INT16>(lhs, rhs);
  }
  static const cpp_type* min_value() {
    return &MathLimits<cpp_type>::kMin;
  }
};

template<>
struct DataTypeTraits<UINT32> {
  static const DataType physical_type = UINT32;
  typedef uint32_t cpp_type;
  static const char *name() {
    return "uint32";
  }
  static void AppendDebugStringForValue(const void *val, string *str) {
    str->append(SimpleItoa(*reinterpret_cast<const uint32_t *>(val)));
  }
  static int Compare(const void *lhs, const void *rhs) {
    return GenericCompare<UINT32>(lhs, rhs);
  }
  static const cpp_type* min_value() {
    return &MathLimits<cpp_type>::kMin;
  }
};

template<>
struct DataTypeTraits<INT32> {
  static const DataType physical_type = INT32;
  typedef int32_t cpp_type;
  static const char *name() {
    return "int32";
  }
  static void AppendDebugStringForValue(const void *val, string *str) {
    str->append(SimpleItoa(*reinterpret_cast<const int32_t *>(val)));
  }
  static int Compare(const void *lhs, const void *rhs) {
    return GenericCompare<INT32>(lhs, rhs);
  }
  static const cpp_type* min_value() {
    return &MathLimits<cpp_type>::kMin;
  }
};

template<>
struct DataTypeTraits<UINT64> {
  static const DataType physical_type = UINT64;
  typedef uint64_t cpp_type;
  static const char *name() {
    return "uint64";
  }
  static void AppendDebugStringForValue(const void *val, string *str) {
    str->append(SimpleItoa(*reinterpret_cast<const uint64_t *>(val)));
  }
  static int Compare(const void *lhs, const void *rhs) {
    return GenericCompare<UINT64>(lhs, rhs);
  }
  static const cpp_type* min_value() {
    return &MathLimits<cpp_type>::kMin;
  }
};

template<>
struct DataTypeTraits<INT64> {
  static const DataType physical_type = INT64;
  typedef int64_t cpp_type;
  static const char *name() {
    return "int64";
  }
  static void AppendDebugStringForValue(const void *val, string *str) {
    str->append(SimpleItoa(*reinterpret_cast<const int64_t *>(val)));
  }
  static int Compare(const void *lhs, const void *rhs) {
    return GenericCompare<INT64>(lhs, rhs);
  }
  static const cpp_type* min_value() {
    return &MathLimits<cpp_type>::kMin;
  }
};

template<>
struct DataTypeTraits<FLOAT> {
  static const DataType physical_type = FLOAT;
  typedef float cpp_type;
  static const char *name() {
    return "float";
  }
  static void AppendDebugStringForValue(const void *val, string *str) {
    str->append(SimpleFtoa(*reinterpret_cast<const float *>(val)));
  }
  static int Compare(const void *lhs, const void *rhs) {
    return GenericCompare<FLOAT>(lhs, rhs);
  }
  static const cpp_type* min_value() {
    return &MathLimits<cpp_type>::kMin;
  }
};

template<>
struct DataTypeTraits<DOUBLE> {
  static const DataType physical_type = DOUBLE;
  typedef double cpp_type;
  static const char *name() {
    return "double";
  }
  static void AppendDebugStringForValue(const void *val, string *str) {
    str->append(SimpleDtoa(*reinterpret_cast<const double *>(val)));
  }
  static int Compare(const void *lhs, const void *rhs) {
    return GenericCompare<DOUBLE>(lhs, rhs);
  }
  static const cpp_type* min_value() {
    return &MathLimits<cpp_type>::kMin;
  }
};

template<>
struct DataTypeTraits<BINARY> {
  static const DataType physical_type = BINARY;
  typedef Slice cpp_type;
  static const char *name() {
    return "binary";
  }
  static void AppendDebugStringForValue(const void *val, string *str) {
    const Slice *s = reinterpret_cast<const Slice *>(val);
    str->append(strings::Utf8SafeCEscape(s->ToString()));
  }

  static int Compare(const void *lhs, const void *rhs) {
    const Slice *lhs_slice = reinterpret_cast<const Slice *>(lhs);
    const Slice *rhs_slice = reinterpret_cast<const Slice *>(rhs);
    return lhs_slice->compare(*rhs_slice);
  }
  static const cpp_type* min_value() {
    static Slice s("");
    return &s;
  }
};

template<>
struct DataTypeTraits<BOOL> {
  static const DataType physical_type = BOOL;
  typedef bool cpp_type;
  static const char* name() {
    return "bool";
  }
  static void AppendDebugStringForValue(const void* val, string* str) {
    str->append(*reinterpret_cast<const bool *>(val) ? "true" : "false");
  }

  static int Compare(const void *lhs, const void *rhs) {
    return GenericCompare<BOOL>(lhs, rhs);
  }
  static const cpp_type* min_value() {
    static bool b = false;
    return &b;
  }
};

// Base class for types that are derived, that is that have some other type as the
// physical representation.
template<DataType PhysicalType>
struct DerivedTypeTraits {
  typedef typename DataTypeTraits<PhysicalType>::cpp_type cpp_type;
  static const DataType physical_type = PhysicalType;

  static void AppendDebugStringForValue(const void *val, string *str) {
    DataTypeTraits<PhysicalType>::AppendDebugStringForValue(val, str);
  }

  static int Compare(const void *lhs, const void *rhs) {
    return DataTypeTraits<PhysicalType>::Compare(lhs, rhs);
  }

  static const cpp_type* min_value() {
    return DataTypeTraits<PhysicalType>::min_value();
  }
};

template<>
struct DataTypeTraits<STRING> : public DerivedTypeTraits<BINARY>{
  static const char* name() {
    return "string";
  }
};

template<>
struct DataTypeTraits<TIMESTAMP> : public DerivedTypeTraits<INT64>{
  static const char* name() {
    return "timestamp";
  }

  static void AppendDebugStringForValue(const void* val, string* str) {
    // TODO KUDU-980 - This only stringifies down to seconds,
    // we should also print the micros.
    time_t time = *reinterpret_cast<const int64_t *>(val);
    char time_as_string[kFastToBufferSize];
    FastTimeToBuffer(time, &time_as_string[0]);
    str->append(time_as_string);
  }
};

// Instantiate this template to get static access to the type traits.
template<DataType datatype>
struct TypeTraits : public DataTypeTraits<datatype> {
  typedef typename DataTypeTraits<datatype>::cpp_type cpp_type;

  static const DataType type = datatype;
  static const size_t size = sizeof(cpp_type);
};

class Variant {
 public:
  Variant(DataType type, const void *value) {
    Reset(type, value);
  }

  ~Variant() {
    Clear();
  }

  template<DataType Type>
  void Reset(const typename DataTypeTraits<Type>::cpp_type& value) {
    Reset(Type, &value);
  }

  // Set the variant to the specified type/value.
  // The value must be of the relative type.
  // In case of strings, the value must be a pointer to a Slice, and the data block
  // will be copied, and released by the variant on the next set/clear call.
  //
  //  Examples:
  //      uint16_t u16 = 512;
  //      Slice slice("Hello World");
  //      variant.set(UINT16, &u16);
  //      variant.set(STRING, &slice);
  void Reset(DataType type, const void *value) {
    CHECK(value != NULL) << "Variant value must be not NULL";
    Clear();
    type_ = type;
    switch (type_) {
      case UNKNOWN_DATA:
        LOG(FATAL) << "Unreachable";
      case BOOL:
        numeric_.b1 = *static_cast<const bool *>(value);
        break;
      case INT8:
        numeric_.i8 = *static_cast<const int8_t *>(value);
        break;
      case UINT8:
        numeric_.u8 = *static_cast<const uint8_t *>(value);
        break;
      case INT16:
        numeric_.i16 = *static_cast<const int16_t *>(value);
        break;
      case UINT16:
        numeric_.u16 = *static_cast<const uint16_t *>(value);
        break;
      case INT32:
        numeric_.i32 = *static_cast<const int32_t *>(value);
        break;
      case UINT32:
        numeric_.u32 = *static_cast<const uint32_t *>(value);
        break;
      case TIMESTAMP:
      case INT64:
        numeric_.i64 = *static_cast<const int64_t *>(value);
        break;
      case UINT64:
        numeric_.u64 = *static_cast<const uint64_t *>(value);
        break;
      case FLOAT:
        numeric_.float_val = *static_cast<const float *>(value);
        break;
      case DOUBLE:
        numeric_.double_val = *static_cast<const double *>(value);
        break;
      case STRING: // Fallthrough intended.
      case BINARY:
        {
          const Slice *str = static_cast<const Slice *>(value);
          if (str->size() > 0) {
            uint8_t *blob = new uint8_t[str->size()];
            memcpy(blob, str->data(), str->size());
            vstr_ = Slice(blob, str->size());
          }
        }
        break;
      default: LOG(FATAL) << "Unknown data type: " << type_;
    }
  }

  // Set the variant to a STRING type.
  // The specified data block will be copied, and released by the variant
  // on the next set/clear call.
  void Reset(const string& data) {
    Slice slice(data);
    Reset(STRING, &slice);
  }

  // Set the variant to a STRING type.
  // The specified data block will be copied, and released by the variant
  // on the next set/clear call.
  void Reset(const char *data, size_t size) {
    Slice slice(data, size);
    Reset(STRING, &slice);
  }

  // Returns the type of the Variant
  DataType type() const {
    return type_;
  }

  // Returns a pointer to the internal variant value
  // The return value can be casted to the relative type()
  // The return value will be valid until the next set() is called.
  //
  //  Examples:
  //    static_cast<const int32_t *>(variant.value())
  //    static_cast<const Slice *>(variant.value())
  const void *value() const {
    switch (type_) {
      case UNKNOWN_DATA: LOG(FATAL) << "Attempted to access value of unknown data type";
      case BOOL:         return &(numeric_.b1);
      case INT8:         return &(numeric_.i8);
      case UINT8:        return &(numeric_.u8);
      case INT16:        return &(numeric_.i16);
      case UINT16:       return &(numeric_.u16);
      case INT32:        return &(numeric_.i32);
      case UINT32:       return &(numeric_.u32);
      case INT64:        return &(numeric_.i64);
      case UINT64:       return &(numeric_.u64);
      case FLOAT:        return (&numeric_.float_val);
      case DOUBLE:       return (&numeric_.double_val);
      case STRING:
      case BINARY:       return &vstr_;
      default: LOG(FATAL) << "Unknown data type: " << type_;
    }
    CHECK(false) << "not reached!";
    return NULL;
  }

  bool Equals(const Variant *other) const {
    if (other == NULL || type_ != other->type_)
      return false;
    return GetTypeInfo(type_)->Compare(value(), other->value()) == 0;
  }

 private:
  DISALLOW_COPY_AND_ASSIGN(Variant);

  void Clear() {
    if (vstr_.size() > 0) {
      delete[] vstr_.mutable_data();
      vstr_.clear();
    }
  }

  union NumericValue {
    bool     b1;
    int8_t   i8;
    uint8_t  u8;
    int16_t  i16;
    uint16_t u16;
    int32_t  i32;
    uint32_t u32;
    int64_t  i64;
    uint64_t u64;
    float    float_val;
    double   double_val;
  };

  DataType type_;
  NumericValue numeric_;
  Slice vstr_;
};

}  // namespace kudu

#endif
