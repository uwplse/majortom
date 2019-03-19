// Copyright (c) 2014, Cloudera, inc.
// Confidential Cloudera Information: Covered by NDA.
#ifndef KUDU_TABLET_MULTI_COLUMN_WRITER_H
#define KUDU_TABLET_MULTI_COLUMN_WRITER_H

#include <glog/logging.h>
#include <tr1/unordered_map>
#include <vector>

#include "kudu/fs/fs_manager.h"
#include "kudu/gutil/macros.h"

namespace kudu {

class RowBlock;
class Schema;

namespace cfile {
class CFileWriter;
} // namespace cfile

namespace fs {
class ScopedWritableBlockCloser;
} // namespace fs

namespace tablet {

// Wrapper which writes several columns in parallel corresponding to some
// Schema.
class MultiColumnWriter {
 public:
  MultiColumnWriter(FsManager* fs,
                    const Schema* schema);

  virtual ~MultiColumnWriter();

  // Open and start writing the columns.
  Status Open();

  // Append the given block to the output columns.
  //
  // Note that the selection vector here is ignored.
  Status AppendBlock(const RowBlock& block);

  // Close the in-progress files.
  //
  // The file's blocks may be retrieved using FlushedBlocks().
  Status Finish();

  // Close the in-progress CFiles, releasing the underlying writable blocks
  // to 'closer'.
  Status FinishAndReleaseBlocks(fs::ScopedWritableBlockCloser* closer);

  // Return the number of bytes written so far.
  size_t written_size() const;

  cfile::CFileWriter* writer_for_col_idx(int i) {
    DCHECK_LT(i, cfile_writers_.size());
    return cfile_writers_[i];
  }

  // Return the block IDs of the written columns, keyed by column ID.
  //
  // REQUIRES: Finish() already called.
  void GetFlushedBlocksByColumnId(std::tr1::unordered_map<int, BlockId>* ret) const;

 private:
  FsManager* const fs_;
  const Schema* const schema_;

  bool finished_;

  std::vector<cfile::CFileWriter *> cfile_writers_;
  std::vector<BlockId> block_ids_;

  DISALLOW_COPY_AND_ASSIGN(MultiColumnWriter);
};

} // namespace tablet
} // namespace kudu
#endif /* KUDU_TABLET_MULTI_COLUMN_WRITER_H */
