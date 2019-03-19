// Copyright (c) 2014, Cloudera, inc.
// Confidential Cloudera Information: Covered by NDA.
#ifndef KUDU_CLIENT_SCAN_PREDICATE_H
#define KUDU_CLIENT_SCAN_PREDICATE_H

#ifdef KUDU_HEADERS_NO_STUBS
#include "kudu/gutil/macros.h"
#include "kudu/gutil/port.h"
#else
#include "kudu/client/stubs.h"
#endif

#include "kudu/client/schema.h"
#include "kudu/util/kudu_export.h"

namespace kudu {
namespace client {

class KUDU_EXPORT KuduPredicate {
 public:
  enum ComparisonOp {
    LESS_EQUAL,
    GREATER_EQUAL,
    EQUAL
  };

  ~KuduPredicate();

  // Returns a new, identical, KuduPredicate.
  KuduPredicate* Clone() const;

  // The PIMPL class has to be public since it's actually just an interface,
  // and gcc gives an error trying to derive from a private nested class.
  class KUDU_NO_EXPORT Data;
 private:
  friend class KuduScanner;
  friend class KuduTable;
  friend class ComparisonPredicateData;
  friend class ErrorPredicateData;

  explicit KuduPredicate(Data* d);

  Data* data_;
  DISALLOW_COPY_AND_ASSIGN(KuduPredicate);
};

} // namespace client
} // namespace kudu
#endif // KUDU_CLIENT_SCAN_PREDICATE_H
