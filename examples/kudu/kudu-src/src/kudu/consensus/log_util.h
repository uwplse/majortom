// Copyright (c) 2013, Cloudera, inc.
// Confidential Cloudera Information: Covered by NDA.

#ifndef KUDU_CONSENSUS_LOG_UTIL_H_
#define KUDU_CONSENSUS_LOG_UTIL_H_

#include <iosfwd>
#include <gtest/gtest.h>
#include <map>
#include <string>
#include <tr1/memory>
#include <utility>
#include <vector>

#include "kudu/consensus/log.pb.h"
#include "kudu/consensus/ref_counted_replicate.h"
#include "kudu/gutil/macros.h"
#include "kudu/gutil/ref_counted.h"
#include "kudu/util/atomic.h"
#include "kudu/util/env.h"

// Used by other classes, now part of the API.
DECLARE_bool(log_force_fsync_all);

namespace kudu {

namespace consensus {
struct OpIdBiggerThanFunctor;
} // namespace consensus

namespace log {

// Suffix for temprorary files
extern const char kTmpSuffix[];

// Each log entry is prefixed by its length (4 bytes), CRC (4 bytes),
// and checksum of the other two fields (see EntryHeader struct below).
extern const size_t kEntryHeaderSize;

extern const int kLogMajorVersion;
extern const int kLogMinorVersion;

class ReadableLogSegment;

// Options for the State Machine/Write Ahead Log
struct LogOptions {

  // The size of a Log segment
  // Logs will rollover upon reaching this size (default 64 MB)
  size_t segment_size_mb;

  // Whether to call fsync on every call to Append().
  bool force_fsync_all;

  // Whether to fallocate segments before writing to them.
  bool preallocate_segments;

  // Whether the allocation should happen asynchronously.
  bool async_preallocate_segments;

  LogOptions();
};


// A sequence of segments, ordered by increasing sequence number.
typedef std::vector<scoped_refptr<ReadableLogSegment> > SegmentSequence;

// A segment of the log can either be a ReadableLogSegment (for replay and
// consensus catch-up) or a WritableLogSegment (where the Log actually stores
// state). LogSegments have a maximum size defined in LogOptions (set from the
// log_segment_size_mb flag, which defaults to 64). Upon reaching this size
// segments are rolled over and the Log continues in a new segment.

// A readable log segment for recovery and follower catch-up.
class ReadableLogSegment : public RefCountedThreadSafe<ReadableLogSegment> {
 public:
  // Factory method to construct a ReadableLogSegment from a file on the FS.
  static Status Open(Env* env,
                     const std::string& path,
                     scoped_refptr<ReadableLogSegment>* segment);

  // Build a readable segment to read entries from the provided path.
  ReadableLogSegment(const std::string &path,
                     const std::tr1::shared_ptr<RandomAccessFile>& readable_file);

  // Initialize the ReadableLogSegment.
  // This initializer provides methods for avoiding disk IO when creating a
  // ReadableLogSegment for the current WritableLogSegment, i.e. for reading
  // the log entries in the same segment that is currently being written to.
  Status Init(const LogSegmentHeaderPB& header,
              int64_t first_entry_offset);

  // Initialize the ReadableLogSegment.
  // This initializer provides methods for avoiding disk IO when creating a
  // ReadableLogSegment from a WritableLogSegment (i.e. for log rolling).
  Status Init(const LogSegmentHeaderPB& header,
              const LogSegmentFooterPB& footer,
              int64_t first_entry_offset);

  // Initialize the ReadableLogSegment.
  // This initializer will parse the log segment header and footer.
  // Note: This returns Status and may fail.
  Status Init();

  // Reads all entries of the provided segment & adds them the 'entries' vector.
  // The 'entries' vector owns the read entries.
  //
  // If the log is corrupted (i.e. the returned 'Status' is 'Corruption') all
  // the log entries read up to the corrupted one are returned in the 'entries'
  // vector.
  //
  // If 'end_offset' is not NULL, then returns the file offset following the last
  // successfully read entry.
  Status ReadEntries(std::vector<LogEntryPB*>* entries,
                     int64_t* end_offset = NULL);

  // Rebuilds this segment's footer by scanning its entries.
  // This is an expensive operation as it reads and parses the whole segment
  // so it should be only used in the case of a crash, where the footer is
  // missing because we didn't have the time to write it out.
  Status RebuildFooterByScanning();

  bool IsInitialized() const {
    return is_initialized_;
  }

  // Returns the parent directory where log segments are stored.
  const std::string &path() const {
    return path_;
  }

  const LogSegmentHeaderPB& header() const {
    DCHECK(header_.IsInitialized());
    return header_;
  }

  // Indicates whether this segment has a footer.
  //
  // Segments that were properly closed, e.g. because they were rolled over,
  // will have properly written footers. On the other hand if there was a
  // crash and the segment was not closed properly the footer will be missing.
  // In this case calling ReadEntries() will rebuild the footer.
  bool HasFooter() const {
    return footer_.IsInitialized();
  }

  // Returns this log segment's footer.
  //
  // If HasFooter() returns false this cannot be called.
  const LogSegmentFooterPB& footer() const {
    DCHECK(IsInitialized());
    CHECK(HasFooter());
    return footer_;
  }

  const std::tr1::shared_ptr<RandomAccessFile> readable_file() const {
    return readable_file_;
  }

  const int64_t file_size() const {
    return file_size_.Load();
  }

  const int64_t first_entry_offset() const {
    return first_entry_offset_;
  }

  // Returns the full size of the file, if the segment is closed and has
  // a footer, or the offset where the last written, non corrupt entry
  // ends.
  const int64_t readable_up_to() const;

 private:
  friend class RefCountedThreadSafe<ReadableLogSegment>;
  friend class LogReader;
  FRIEND_TEST(LogTest, TestWriteAndReadToAndFromInProgressSegment);

  struct EntryHeader {
    // The length of the batch data.
    uint32_t msg_length;

    // The CRC32C of the batch data.
    uint32_t msg_crc;

    // The CRC32C of this EntryHeader.
    uint32_t header_crc;
  };

  ~ReadableLogSegment() {}

  // Helper functions called by Init().

  Status ReadFileSize();

  Status ReadHeader();

  Status ReadHeaderMagicAndHeaderLength(uint32_t *len);

  Status ParseHeaderMagicAndHeaderLength(const Slice &data, uint32_t *parsed_len);

  Status ReadFooter();

  Status ReadFooterMagicAndFooterLength(uint32_t *len);

  Status ParseFooterMagicAndFooterLength(const Slice &data, uint32_t *parsed_len);

  // Starting at 'offset', read the rest of the log file, looking for any
  // valid log entry headers. If any are found, sets *has_valid_entries to true.
  //
  // Returns a bad Status only in the case that some IO error occurred reading the
  // file.
  Status ScanForValidEntryHeaders(int64_t offset, bool* has_valid_entries);

  // Format a nice error message to report on a corruption in a log file.
  Status MakeCorruptionStatus(int batch_number, int64_t batch_offset,
                              std::vector<int64_t>* recent_offsets,
                              const std::vector<LogEntryPB*>& entries,
                              const Status& status) const;

  Status ReadEntryHeaderAndBatch(int64_t* offset, faststring* tmp_buf,
                                 gscoped_ptr<LogEntryBatchPB>* batch);

  // Reads a log entry header from the segment.
  // Also increments the passed offset* by the length of the entry.
  Status ReadEntryHeader(int64_t *offset, EntryHeader* header);

  // Decode a log entry header from the given slice, which must be kEntryHeaderSize
  // bytes long. Returns true if successful, false if corrupt.
  //
  // NOTE: this is performance-critical since it is used by ScanForValidEntryHeaders
  // and thus returns bool instead of Status.
  bool DecodeEntryHeader(const Slice& data, EntryHeader* header);


  // Reads a log entry batch from the provided readable segment, which gets decoded
  // into 'entry_batch' and increments 'offset' by the batch's length.
  Status ReadEntryBatch(int64_t *offset,
                        const EntryHeader& header,
                        faststring* tmp_buf,
                        gscoped_ptr<LogEntryBatchPB>* entry_batch);

  void UpdateReadableToOffset(int64_t readable_to_offset);

  const std::string path_;

  // The size of the readable file.
  // This is set by Init(). In the case of a log being written to,
  // this may be increased by UpdateReadableToOffset()
  AtomicInt<int64_t> file_size_;

  // The offset up to which we can read the file.
  // For already written segments this is fixed and equal to the file size
  // but for the segments currently written to this is the offset up to which
  // we can read without the fear of reading garbage/zeros.
  // This is atomic because the Log thread might be updating the segment's readable
  // offset while an async reader is reading the segment's entries.
  // is reading it.
  AtomicInt<int64_t> readable_to_offset_;

  // a readable file for a log segment (used on replay)
  const std::tr1::shared_ptr<RandomAccessFile> readable_file_;

  bool is_initialized_;

  LogSegmentHeaderPB header_;

  LogSegmentFooterPB footer_;

  // True if the footer was rebuilt, rather than actually found on disk.
  bool footer_was_rebuilt_;

  // the offset of the first entry in the log
  int64_t first_entry_offset_;

  DISALLOW_COPY_AND_ASSIGN(ReadableLogSegment);
};

// A writable log segment where state data is stored.
class WritableLogSegment {
 public:
  WritableLogSegment(const std::string &path,
                     const std::tr1::shared_ptr<WritableFile>& writable_file);

  // Opens the segment by writing the header.
  Status WriteHeaderAndOpen(const LogSegmentHeaderPB& new_header);

  // Closes the segment by writing the footer and then actually closing the
  // underlying WritableFile.
  Status WriteFooterAndClose(const LogSegmentFooterPB& footer);

  bool IsClosed() {
    return IsHeaderWritten() && IsFooterWritten();
  }

  int64_t Size() const {
    return writable_file_->Size();
  }

  // Appends the provided batch of data, including a header
  // and checksum.
  // Makes sure that the log segment has not been closed.
  Status WriteEntryBatch(const Slice& entry_batch_data);

  // Makes sure the I/O buffers in the underlying writable file are flushed.
  Status Sync() {
    return writable_file_->Sync();
  }

  // Returns true if the segment header has already been written to disk.
  bool IsHeaderWritten() const {
    return is_header_written_;
  }

  const LogSegmentHeaderPB& header() const {
    DCHECK(IsHeaderWritten());
    return header_;
  }

  bool IsFooterWritten() const {
    return is_footer_written_;
  }

  const LogSegmentFooterPB& footer() const {
    DCHECK(IsFooterWritten());
    return footer_;
  }

  // Returns the parent directory where log segments are stored.
  const std::string &path() const {
    return path_;
  }

  const int64_t first_entry_offset() const {
    return first_entry_offset_;
  }

  const int64_t written_offset() const {
    return written_offset_;
  }

 private:

  const std::tr1::shared_ptr<WritableFile>& writable_file() const {
    return writable_file_;
  }

  // The path to the log file.
  const std::string path_;

  // The writable file to which this LogSegment will be written.
  const std::tr1::shared_ptr<WritableFile> writable_file_;

  bool is_header_written_;

  bool is_footer_written_;

  LogSegmentHeaderPB header_;

  LogSegmentFooterPB footer_;

  // the offset of the first entry in the log
  int64_t first_entry_offset_;

  // The offset where the last written entry ends.
  int64_t written_offset_;

  DISALLOW_COPY_AND_ASSIGN(WritableLogSegment);
};

// Sets 'batch' to a newly created batch that contains the pre-allocated
// ReplicateMsgs in 'msgs'.
// We use C-style passing here to avoid having to allocate a vector
// in some hot paths.
void CreateBatchFromAllocatedOperations(const std::vector<consensus::ReplicateRefPtr>& msgs,
                                        gscoped_ptr<LogEntryBatchPB>* batch);

// Checks if 'fname' is a correctly formatted name of log segment file.
bool IsLogFileName(const std::string& fname);

}  // namespace log
}  // namespace kudu

#endif /* KUDU_CONSENSUS_LOG_UTIL_H_ */
