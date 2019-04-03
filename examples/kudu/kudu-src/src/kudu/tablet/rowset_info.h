// Copyright (c) 2013, Cloudera, inc.
// Confidential Cloudera Information: Covered by NDA.
#ifndef KUDU_TABLET_ROWSET_INFO_H_
#define KUDU_TABLET_ROWSET_INFO_H_

#include <string>
#include <vector>

namespace kudu {
namespace tablet {

class RowSet;
class RowSetTree;

// Class used to cache some computed statistics on a RowSet used
// during evaluation of budgeted compaction policy.
//
// Class is immutable.
class RowSetInfo {
 public:

  // Appends the rowsets in no order without the cdf values set.
  static void Collect(const RowSetTree& tree, std::vector<RowSetInfo>* rsvec);
  // Appends the rowsets in min-key and max-key sorted order, with
  // cdf values set.
  static void CollectOrdered(const RowSetTree& tree,
                             std::vector<RowSetInfo>* min_key,
                             std::vector<RowSetInfo>* max_key);

  int size_mb() const { return size_mb_; }

  // Return the value of the CDF at the minimum key of this candidate.
  double cdf_min_key() const { return cdf_min_key_; }
  // Return the value of the CDF at the maximum key of this candidate.
  double cdf_max_key() const { return cdf_max_key_; }

  // Return the "width" of the candidate rowset.
  //
  // This is an estimate of the percentage of the tablet data which
  // is spanned by this RowSet, calculated by integrating the
  // probability distribution function across this rowset's keyrange.
  double width() const {
    return cdf_max_key_ - cdf_min_key_;
  }

  double density() const { return density_; }

  RowSet* rowset() const { return rowset_; }

  std::string ToString() const;

  // Return true if this candidate overlaps the other candidate in
  // the computed cdf interval. To check intersection in key space,
  // use this instance's rowset()->GetBounds().
  // The two intersection results may not agree because of floating
  // point error in the cdf calculation.
  bool Intersects(const RowSetInfo& other) const;

 private:
  explicit RowSetInfo(RowSet* rs, double init_cdf);

  static void FinalizeCDFVector(std::vector<RowSetInfo>* vec,
                                double quot);

  RowSet* rowset_;
  int size_mb_;
  double cdf_min_key_, cdf_max_key_;
  double density_;
};

} // namespace tablet
} // namespace kudu

#endif
