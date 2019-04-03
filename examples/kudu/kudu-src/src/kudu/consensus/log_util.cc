// Copyright (c) 2013, Cloudera, inc.
// Confidential Cloudera Information: Covered by NDA.

#include "kudu/consensus/log_util.h"

#include <algorithm>
#include <boost/foreach.hpp>
#include <iostream>
#include <limits>
#include <utility>

#include <gflags/gflags.h>
#include <glog/logging.h>

#include "kudu/consensus/opid_util.h"
#include "kudu/consensus/ref_counted_replicate.h"
#include "kudu/fs/fs_manager.h"
#include "kudu/gutil/map-util.h"
#include "kudu/gutil/stl_util.h"
#include "kudu/gutil/strings/substitute.h"
#include "kudu/gutil/strings/util.h"
#include "kudu/gutil/strings/split.h"
#include "kudu/util/coding.h"
#include "kudu/util/coding-inl.h"
#include "kudu/util/crc.h"
#include "kudu/util/debug/trace_event.h"
#include "kudu/util/env_util.h"
#include "kudu/util/flag_tags.h"
#include "kudu/util/pb_util.h"

DEFINE_int32(log_segment_size_mb, 64,
             "The default segment size for log roll-overs, in MB");
TAG_FLAG(log_segment_size_mb, advanced);

DEFINE_bool(log_force_fsync_all, false,
            "Whether the Log/WAL should explicitly call fsync() after each write.");
TAG_FLAG(log_force_fsync_all, stable);

DEFINE_bool(log_preallocate_segments, true,
            "Whether the WAL should preallocate the entire segment before writing to it");
TAG_FLAG(log_preallocate_segments, advanced);

DEFINE_bool(log_async_preallocate_segments, true,
            "Whether the WAL segments preallocation should happen asynchronously");
TAG_FLAG(log_async_preallocate_segments, advanced);

namespace kudu {
namespace log {

using consensus::OpId;
using env_util::ReadFully;
using std::vector;
using std::tr1::shared_ptr;
using strings::Substitute;
using strings::SubstituteAndAppend;

const char kTmpSuffix[] = ".tmp";

const char kLogSegmentHeaderMagicString[] = "kudulogf";

// A magic that is written as the very last thing when a segment is closed.
// Segments that were not closed (usually the last one being written) will not
// have this magic.
const char kLogSegmentFooterMagicString[] = "closedls";

// Header is prefixed with the header magic (8 bytes) and the header length (4 bytes).
const size_t kLogSegmentHeaderMagicAndHeaderLength = 12;

// Footer is suffixed with the footer magic (8 bytes) and the footer length (4 bytes).
const size_t kLogSegmentFooterMagicAndFooterLength  = 12;

const size_t kEntryHeaderSize = 12;

const int kLogMajorVersion = 1;
const int kLogMinorVersion = 0;

// Maximum log segment header/footer size, in bytes (8 MB).
const uint32_t kLogSegmentMaxHeaderOrFooterSize = 8 * 1024 * 1024;

LogOptions::LogOptions()
: segment_size_mb(FLAGS_log_segment_size_mb),
  force_fsync_all(FLAGS_log_force_fsync_all),
  preallocate_segments(FLAGS_log_preallocate_segments),
  async_preallocate_segments(FLAGS_log_async_preallocate_segments) {
}

Status ReadableLogSegment::Open(Env* env,
                                const string& path,
                                scoped_refptr<ReadableLogSegment>* segment) {
  VLOG(1) << "Parsing wal segment: " << path;
  shared_ptr<RandomAccessFile> readable_file;
  RETURN_NOT_OK_PREPEND(env_util::OpenFileForRandom(env, path, &readable_file),
                        "Unable to open file for reading");

  segment->reset(new ReadableLogSegment(path, readable_file));
  RETURN_NOT_OK_PREPEND((*segment)->Init(), "Unable to initialize segment");
  return Status::OK();
}

ReadableLogSegment::ReadableLogSegment(const std::string &path,
                                       const shared_ptr<RandomAccessFile>& readable_file)
  : path_(path),
    file_size_(0),
    readable_to_offset_(0),
    readable_file_(readable_file),
    is_initialized_(false),
    footer_was_rebuilt_(false) {
}

Status ReadableLogSegment::Init(const LogSegmentHeaderPB& header,
                                const LogSegmentFooterPB& footer,
                                int64_t first_entry_offset) {
  DCHECK(!IsInitialized()) << "Can only call Init() once";
  DCHECK(header.IsInitialized()) << "Log segment header must be initialized";
  DCHECK(footer.IsInitialized()) << "Log segment footer must be initialized";

  RETURN_NOT_OK(ReadFileSize());

  header_.CopyFrom(header);
  footer_.CopyFrom(footer);
  first_entry_offset_ = first_entry_offset;
  is_initialized_ = true;
  readable_to_offset_.Store(file_size());

  return Status::OK();
}

Status ReadableLogSegment::Init(const LogSegmentHeaderPB& header,
                                int64_t first_entry_offset) {
  DCHECK(!IsInitialized()) << "Can only call Init() once";
  DCHECK(header.IsInitialized()) << "Log segment header must be initialized";

  RETURN_NOT_OK(ReadFileSize());

  header_.CopyFrom(header);
  first_entry_offset_ = first_entry_offset;
  is_initialized_ = true;

  // On a new segment, we don't expect any readable entries yet.
  readable_to_offset_.Store(first_entry_offset);

  return Status::OK();
}

Status ReadableLogSegment::Init() {
  DCHECK(!IsInitialized()) << "Can only call Init() once";

  RETURN_NOT_OK(ReadFileSize());

  RETURN_NOT_OK(ReadHeader());

  Status s = ReadFooter();
  if (!s.ok()) {
    LOG(WARNING) << "Could not read footer for segment: " << path_
        << ": " << s.ToString();
  }

  is_initialized_ = true;

  readable_to_offset_.Store(file_size());

  return Status::OK();
}

const int64_t ReadableLogSegment::readable_up_to() const {
  return readable_to_offset_.Load();
}

void ReadableLogSegment::UpdateReadableToOffset(int64_t readable_to_offset) {
  readable_to_offset_.Store(readable_to_offset);
  file_size_.StoreMax(readable_to_offset);
}

Status ReadableLogSegment::RebuildFooterByScanning() {
  TRACE_EVENT1("log", "ReadableLogSegment::RebuildFooterByScanning",
               "path", path_);

  DCHECK(!footer_.IsInitialized());
  vector<LogEntryPB*> entries;
  ElementDeleter deleter(&entries);
  int64_t end_offset = 0;
  RETURN_NOT_OK(ReadEntries(&entries, &end_offset));

  footer_.set_num_entries(entries.size());

  // Rebuild the min/max replicate index (by scanning)
  BOOST_FOREACH(const LogEntryPB* entry, entries) {
    if (entry->has_replicate()) {
      int64_t index = entry->replicate().id().index();
      // TODO: common code with Log::UpdateFooterForBatch
      if (!footer_.has_min_replicate_index() ||
          index < footer_.min_replicate_index()) {
        footer_.set_min_replicate_index(index);
      }
      if (!footer_.has_max_replicate_index() ||
          index > footer_.max_replicate_index()) {
        footer_.set_max_replicate_index(index);
      }
    }
  }

  DCHECK(footer_.IsInitialized());
  DCHECK_EQ(entries.size(), footer_.num_entries());
  footer_was_rebuilt_ = true;

  readable_to_offset_.Store(end_offset);

  LOG(INFO) << "Successfully rebuilt footer for segment: " << path_
            << " (valid entries through byte offset " << end_offset << ")";
  return Status::OK();
}

Status ReadableLogSegment::ReadFileSize() {
  // Check the size of the file.
  // Env uses uint here, even though we generally prefer signed ints to avoid
  // underflow bugs. Use a local to convert.
  uint64_t size;
  RETURN_NOT_OK_PREPEND(readable_file_->Size(&size), "Unable to read file size");
  file_size_.Store(size);
  if (size == 0) {
    VLOG(1) << "Log segment file $0 is zero-length: " << path();
    return Status::OK();
  }
  return Status::OK();
}

Status ReadableLogSegment::ReadHeader() {
  uint32_t header_size;
  RETURN_NOT_OK(ReadHeaderMagicAndHeaderLength(&header_size));
  if (header_size == 0) {
    // If a log file has been pre-allocated but not initialized, then
    // 'header_size' will be 0 even the file size is > 0; in this
    // case, 'is_initialized_' remains set to false and return
    // Status::OK() early. LogReader ignores segments where
    // IsInitialized() returns false.
    return Status::OK();
  }

  if (header_size > kLogSegmentMaxHeaderOrFooterSize) {
    return Status::Corruption(
        Substitute("File is corrupted. "
                   "Parsed header size: $0 is zero or bigger than max header size: $1",
                   header_size, kLogSegmentMaxHeaderOrFooterSize));
  }

  uint8_t header_space[header_size];
  Slice header_slice;
  LogSegmentHeaderPB header;

  // Read and parse the log segment header.
  RETURN_NOT_OK_PREPEND(ReadFully(readable_file_.get(), kLogSegmentHeaderMagicAndHeaderLength,
                                  header_size, &header_slice, header_space),
                        "Unable to read fully");

  RETURN_NOT_OK_PREPEND(pb_util::ParseFromArray(&header,
                                                header_slice.data(),
                                                header_size),
                        "Unable to parse protobuf");

  header_.CopyFrom(header);
  first_entry_offset_ = header_size + kLogSegmentHeaderMagicAndHeaderLength;

  return Status::OK();
}


Status ReadableLogSegment::ReadHeaderMagicAndHeaderLength(uint32_t *len) {
  uint8_t scratch[kLogSegmentHeaderMagicAndHeaderLength];
  Slice slice;
  RETURN_NOT_OK(ReadFully(readable_file_.get(), 0, kLogSegmentHeaderMagicAndHeaderLength,
                          &slice, scratch));
  RETURN_NOT_OK(ParseHeaderMagicAndHeaderLength(slice, len));
  return Status::OK();
}

namespace {

// We don't run TSAN on this function because it makes it really slow and causes some
// test timeouts. This is only used on local buffers anyway, so we don't lose much
// by not checking it.
ATTRIBUTE_NO_SANITIZE_THREAD
bool IsAllZeros(const Slice& s) {
  // Walk a pointer through the slice instead of using s[i]
  // since this is way faster in debug mode builds. We also do some
  // manual unrolling for the same purpose.
  const uint8_t* p = &s[0];
  int rem = s.size();

  while (rem >= 8) {
    if (UNALIGNED_LOAD64(p) != 0) return false;
    rem -= 8;
    p += 8;
  }

  while (rem > 0) {
    if (*p++ != '\0') return false;
    rem--;
  }
  return true;
}
} // anonymous namespace

Status ReadableLogSegment::ParseHeaderMagicAndHeaderLength(const Slice &data,
                                                           uint32_t *parsed_len) {
  RETURN_NOT_OK_PREPEND(data.check_size(kLogSegmentHeaderMagicAndHeaderLength),
                        "Log segment file is too small to contain initial magic number");

  if (memcmp(kLogSegmentHeaderMagicString, data.data(),
             strlen(kLogSegmentHeaderMagicString)) != 0) {
    // As a special case, we check whether the file was allocated but no header
    // was written. We treat that case as an uninitialized file, much in the
    // same way we treat zero-length files.
    // Note: While the above comparison checks 8 bytes, this one checks the full 12
    // to ensure we have a full 12 bytes of NULL data.
    if (IsAllZeros(data)) {
      // 12 bytes of NULLs, good enough for us to consider this a file that
      // was never written to (but apparently preallocated).
      LOG(WARNING) << "Log segment file " << path() << " has 12 initial NULL bytes instead of "
                   << "magic and header length: " << data.ToDebugString()
                   << " and will be treated as a blank segment.";
      *parsed_len = 0;
      return Status::OK();
    }
    // If no magic and not uninitialized, the file is considered corrupt.
    return Status::Corruption(Substitute("Invalid log segment file $0: Bad magic. $1",
                                         path(), data.ToDebugString()));
  }

  *parsed_len = DecodeFixed32(data.data() + strlen(kLogSegmentHeaderMagicString));
  return Status::OK();
}

Status ReadableLogSegment::ReadFooter() {
  uint32_t footer_size;
  RETURN_NOT_OK(ReadFooterMagicAndFooterLength(&footer_size));

  if (footer_size == 0 || footer_size > kLogSegmentMaxHeaderOrFooterSize) {
    return Status::NotFound(
        Substitute("File is corrupted. "
                   "Parsed header size: $0 is zero or bigger than max header size: $1",
                   footer_size, kLogSegmentMaxHeaderOrFooterSize));
  }

  if (footer_size > (file_size() - first_entry_offset_)) {
    return Status::NotFound("Footer not found. File corrupted. "
        "Decoded footer length pointed at a footer before the first entry.");
  }

  uint8_t footer_space[footer_size];
  Slice footer_slice;

  int64_t footer_offset = file_size() - kLogSegmentFooterMagicAndFooterLength - footer_size;

  LogSegmentFooterPB footer;

  // Read and parse the log segment footer.
  RETURN_NOT_OK_PREPEND(ReadFully(readable_file_.get(), footer_offset,
                                  footer_size, &footer_slice, footer_space),
                        "Footer not found. Could not read fully.");

  RETURN_NOT_OK_PREPEND(pb_util::ParseFromArray(&footer,
                                                footer_slice.data(),
                                                footer_size),
                        "Unable to parse protobuf");

  footer_.Swap(&footer);
  return Status::OK();
}

Status ReadableLogSegment::ReadFooterMagicAndFooterLength(uint32_t *len) {
  uint8_t scratch[kLogSegmentFooterMagicAndFooterLength];
  Slice slice;

  CHECK_GT(file_size(), kLogSegmentFooterMagicAndFooterLength);
  RETURN_NOT_OK(ReadFully(readable_file_.get(),
                          file_size() - kLogSegmentFooterMagicAndFooterLength,
                          kLogSegmentFooterMagicAndFooterLength,
                          &slice,
                          scratch));

  RETURN_NOT_OK(ParseFooterMagicAndFooterLength(slice, len));
  return Status::OK();
}

Status ReadableLogSegment::ParseFooterMagicAndFooterLength(const Slice &data,
                                                           uint32_t *parsed_len) {
  RETURN_NOT_OK_PREPEND(data.check_size(kLogSegmentFooterMagicAndFooterLength),
                        "Slice is too small to contain final magic number");

  if (memcmp(kLogSegmentFooterMagicString, data.data(),
             strlen(kLogSegmentFooterMagicString)) != 0) {
    return Status::NotFound("Footer not found. Footer magic doesn't match");
  }

  *parsed_len = DecodeFixed32(data.data() + strlen(kLogSegmentFooterMagicString));
  return Status::OK();
}

Status ReadableLogSegment::ReadEntries(vector<LogEntryPB*>* entries,
                                       int64_t* end_offset) {
  TRACE_EVENT1("log", "ReadableLogSegment::ReadEntries",
               "path", path_);

  vector<int64_t> recent_offsets(4, -1);
  int batches_read = 0;

  int64_t offset = first_entry_offset();
  int64_t readable_to_offset = readable_to_offset_.Load();
  VLOG(1) << "Reading segment entries from "
          << path_ << ": offset=" << offset << " file_size="
          << file_size() << " readable_to_offset=" << readable_to_offset;
  faststring tmp_buf;

  // If we have a footer we only read up to it. If we don't we likely crashed
  // and always read to the end.
  int64_t read_up_to = (footer_.IsInitialized() && !footer_was_rebuilt_) ?
      file_size() - footer_.ByteSize() - kLogSegmentFooterMagicAndFooterLength :
      readable_to_offset;

  if (end_offset != NULL) {
    *end_offset = offset;
  }

  int num_entries_read = 0;
  while (offset < read_up_to) {
    const int64_t this_batch_offset = offset;
    recent_offsets[batches_read++ % recent_offsets.size()] = offset;

    gscoped_ptr<LogEntryBatchPB> current_batch;

    // Read and validate the entry header first.
    Status s;
    if (offset + kEntryHeaderSize < read_up_to) {
      s = ReadEntryHeaderAndBatch(&offset, &tmp_buf, &current_batch);
    } else {
      s = Status::Corruption(Substitute("Truncated log entry at offset $0", offset));
    }

    if (PREDICT_FALSE(!s.ok())) {
      if (!s.IsCorruption()) {
        // IO errors should always propagate back
        return s.CloneAndPrepend(Substitute("Error reading from log $0", path_));
      }

      Status corruption_status = MakeCorruptionStatus(
          batches_read, this_batch_offset, &recent_offsets,
          *entries, s);

      // If we have a valid footer in the segment, then the segment was correctly
      // closed, and we shouldn't see any corruption anywhere (including the last
      // batch).
      if (HasFooter() && !footer_was_rebuilt_) {
        LOG(WARNING) << "Found a corruption in a closed log segment: "
                     << corruption_status.ToString();
        return corruption_status;
      }

      // If we read a corrupt entry, but we don't have a footer, then it's
      // possible that we crashed in the middle of writing an entry.
      // In this case, we scan forward to see if there are any more valid looking
      // entries after this one in the file. If there are, it's really a corruption.
      // if not, we just WARN it, since it's OK for the last entry to be partially
      // written.
      bool has_valid_entries;
      RETURN_NOT_OK_PREPEND(ScanForValidEntryHeaders(offset, &has_valid_entries),
                            "Scanning forward for valid entries");
      if (has_valid_entries) {
        return corruption_status;
      }

      LOG(INFO) << "Ignoring log segment corruption in " << path_ << " because "
                << "there are no log entries following the corrupted one. "
                << "The server probably crashed in the middle of writing an entry "
                << "to the write-ahead log or downloaded an active log via remote bootstrap. "
                << "Error detail: " << corruption_status.ToString();
      break;
    }

    if (VLOG_IS_ON(3)) {
      VLOG(3) << "Read Log entry batch: " << current_batch->DebugString();
    }
    for (size_t i = 0; i < current_batch->entry_size(); ++i) {
      entries->push_back(current_batch->mutable_entry(i));
      num_entries_read++;
    }
    current_batch->mutable_entry()->ExtractSubrange(0,
                                                    current_batch->entry_size(),
                                                    NULL);
    if (end_offset != NULL) {
      *end_offset = offset;
    }
  }

  if (footer_.IsInitialized() && footer_.num_entries() != num_entries_read) {
    return Status::Corruption(
      Substitute("Read $0 log entries from $1, but expected $2 based on the footer",
                 num_entries_read, path_, footer_.num_entries()));
  }

  return Status::OK();
}

Status ReadableLogSegment::ScanForValidEntryHeaders(int64_t offset, bool* has_valid_entries) {
  TRACE_EVENT1("log", "ReadableLogSegment::ScanForValidEntryHeaders",
               "path", path_);
  LOG(INFO) << "Scanning " << path_ << " for valid entry headers "
            << "following offset " << offset << "...";
  *has_valid_entries = false;

  const int kChunkSize = 1024 * 1024;
  gscoped_ptr<uint8_t[]> buf(new uint8_t[kChunkSize]);

  // We overlap the reads by the size of the header, so that if a header
  // spans chunks, we don't miss it.
  for (;
       offset < file_size() - kEntryHeaderSize;
       offset += kChunkSize - kEntryHeaderSize) {
    int rem = std::min<int64_t>(file_size() - offset, kChunkSize);
    Slice chunk;
    RETURN_NOT_OK(ReadFully(readable_file().get(), offset, rem, &chunk, &buf[0]));

    // Optimization for the case where a chunk is all zeros -- this is common in the
    // case of pre-allocated files. This avoids a lot of redundant CRC calculation.
    if (IsAllZeros(chunk)) {
      continue;
    }

    // Check if this chunk has a valid entry header.
    for (int off_in_chunk = 0;
         off_in_chunk < chunk.size() - kEntryHeaderSize;
         off_in_chunk++) {
      Slice potential_header = Slice(&chunk[off_in_chunk], kEntryHeaderSize);

      EntryHeader header;
      if (DecodeEntryHeader(potential_header, &header)) {
        LOG(INFO) << "Found a valid entry header at offset " << (offset + off_in_chunk);
        *has_valid_entries = true;
        return Status::OK();
      }
    }
  }

  LOG(INFO) << "Found no log entry headers";
  return Status::OK();
}

Status ReadableLogSegment::MakeCorruptionStatus(int batch_number, int64_t batch_offset,
                                                vector<int64_t>* recent_offsets,
                                                const std::vector<LogEntryPB*>& entries,
                                                const Status& status) const {

  string err = "Log file corruption detected. ";
  SubstituteAndAppend(&err, "Failed trying to read batch #$0 at offset $1 for log segment $2: ",
                      batch_number, batch_offset, path_);
  err.append("Prior batch offsets:");
  std::sort(recent_offsets->begin(), recent_offsets->end());
  BOOST_FOREACH(int64_t offset, *recent_offsets) {
    if (offset >= 0) {
      SubstituteAndAppend(&err, " $0", offset);
    }
  }
  if (!entries.empty()) {
    err.append("; Last log entries read:");
    const int kNumEntries = 4; // Include up to the last 4 entries in the segment.
    for (int i = std::max(0, static_cast<int>(entries.size()) - kNumEntries);
        i < entries.size(); i++) {
      LogEntryPB* entry = entries[i];
      LogEntryTypePB type = entry->type();
      string opid_str;
      if (type == log::REPLICATE && entry->has_replicate()) {
        opid_str = OpIdToString(entry->replicate().id());
      } else if (entry->has_commit() && entry->commit().has_commited_op_id()) {
        opid_str = OpIdToString(entry->commit().commited_op_id());
      } else {
        opid_str = "<unknown>";
      }
      SubstituteAndAppend(&err, " [$0 ($1)]", LogEntryTypePB_Name(type), opid_str);
    }
  }

  return status.CloneAndAppend(err);
}

Status ReadableLogSegment::ReadEntryHeaderAndBatch(int64_t* offset, faststring* tmp_buf,
                                                   gscoped_ptr<LogEntryBatchPB>* batch) {
  EntryHeader header;
  RETURN_NOT_OK(ReadEntryHeader(offset, &header));
  RETURN_NOT_OK(ReadEntryBatch(offset, header, tmp_buf, batch));
  return Status::OK();
}


Status ReadableLogSegment::ReadEntryHeader(int64_t *offset, EntryHeader* header) {
  uint8_t scratch[kEntryHeaderSize];
  Slice slice;
  RETURN_NOT_OK_PREPEND(ReadFully(readable_file().get(), *offset, kEntryHeaderSize,
                                  &slice, scratch),
                        "Could not read log entry header");

  if (PREDICT_FALSE(!DecodeEntryHeader(slice, header))) {
    return Status::Corruption("CRC mismatch in log entry header");
  }
  *offset += slice.size();
  return Status::OK();
}

bool ReadableLogSegment::DecodeEntryHeader(const Slice& data, EntryHeader* header) {
  DCHECK_EQ(kEntryHeaderSize, data.size());
  header->msg_length = DecodeFixed32(&data[0]);
  header->msg_crc    = DecodeFixed32(&data[4]);
  header->header_crc = DecodeFixed32(&data[8]);

  // Verify the header.
  uint32_t computed_crc = crc::Crc32c(&data[0], 8);
  return computed_crc == header->header_crc;
}


Status ReadableLogSegment::ReadEntryBatch(int64_t *offset,
                                          const EntryHeader& header,
                                          faststring *tmp_buf,
                                          gscoped_ptr<LogEntryBatchPB> *entry_batch) {
  TRACE_EVENT2("log", "ReadableLogSegment::ReadEntryBatch",
               "path", path_,
               "range", Substitute("offset=$0 entry_len=$1",
                                   *offset, header.msg_length));

  if (header.msg_length == 0) {
    return Status::Corruption("Invalid 0 entry length");
  }
  int64_t limit = readable_up_to();
  if (PREDICT_FALSE(header.msg_length + *offset > limit)) {
    // The log was likely truncated during writing.
    return Status::Corruption(
        Substitute("Could not read $0-byte log entry from offset $1 in $2: "
                   "log only readable up to offset $3",
                   header.msg_length, *offset, path_, limit));
  }

  tmp_buf->clear();
  tmp_buf->resize(header.msg_length);
  Slice entry_batch_slice;

  Status s =  readable_file()->Read(*offset,
                                    header.msg_length,
                                    &entry_batch_slice,
                                    tmp_buf->data());

  if (!s.ok()) return Status::IOError(Substitute("Could not read entry. Cause: $0",
                                                 s.ToString()));

  // Verify the CRC.
  uint32_t read_crc = crc::Crc32c(entry_batch_slice.data(), entry_batch_slice.size());
  if (PREDICT_FALSE(read_crc != header.msg_crc)) {
    return Status::Corruption(Substitute("Entry CRC mismatch in byte range $0-$1: "
                                         "expected CRC=$2, computed=$3",
                                         *offset, *offset + header.msg_length,
                                         header.msg_crc, read_crc));
  }


  gscoped_ptr<LogEntryBatchPB> read_entry_batch(new LogEntryBatchPB());
  s = pb_util::ParseFromArray(read_entry_batch.get(),
                              entry_batch_slice.data(),
                              header.msg_length);

  if (!s.ok()) return Status::Corruption(Substitute("Could parse PB. Cause: $0",
                                                    s.ToString()));

  *offset += entry_batch_slice.size();
  entry_batch->reset(read_entry_batch.release());
  return Status::OK();
}


WritableLogSegment::WritableLogSegment(
    const string &path,
    const shared_ptr<WritableFile>& writable_file)
: path_(path),
  writable_file_(writable_file),
  is_header_written_(false),
  is_footer_written_(false),
  written_offset_(0) {
}

Status WritableLogSegment::WriteHeaderAndOpen(const LogSegmentHeaderPB& new_header) {
  DCHECK(!IsHeaderWritten()) << "Can only call WriteHeader() once";
  DCHECK(new_header.IsInitialized())
      << "Log segment header must be initialized" << new_header.InitializationErrorString();
  faststring buf;

  // First the magic.
  buf.append(kLogSegmentHeaderMagicString);
  // Then Length-prefixed header.
  PutFixed32(&buf, new_header.ByteSize());
  // Then Serialize the PB.
  if (!pb_util::AppendToString(new_header, &buf)) {
    return Status::Corruption("unable to encode header");
  }
  RETURN_NOT_OK(writable_file()->Append(Slice(buf)));

  header_.CopyFrom(new_header);
  first_entry_offset_ = buf.size();
  written_offset_ = first_entry_offset_;
  is_header_written_ = true;

  return Status::OK();
}

Status WritableLogSegment::WriteFooterAndClose(const LogSegmentFooterPB& footer) {
  TRACE_EVENT1("log", "WritableLogSegment::WriteFooterAndClose",
               "path", path_);
  DCHECK(IsHeaderWritten());
  DCHECK(!IsFooterWritten());
  DCHECK(footer.IsInitialized()) << footer.InitializationErrorString();

  faststring buf;

  if (!pb_util::AppendToString(footer, &buf)) {
    return Status::Corruption("unable to encode header");
  }

  buf.append(kLogSegmentFooterMagicString);
  PutFixed32(&buf, footer.ByteSize());

  RETURN_NOT_OK_PREPEND(writable_file()->Append(Slice(buf)), "Could not write the footer");

  footer_.CopyFrom(footer);
  is_footer_written_ = true;

  RETURN_NOT_OK(writable_file_->Close());

  written_offset_ += buf.size();

  return Status::OK();
}


Status WritableLogSegment::WriteEntryBatch(const Slice& data) {
  DCHECK(is_header_written_);
  DCHECK(!is_footer_written_);
  uint8_t header_buf[kEntryHeaderSize];

  // First encode the length of the message.
  uint32_t len = data.size();
  InlineEncodeFixed32(&header_buf[0], len);

  // Then the CRC of the message.
  uint32_t msg_crc = crc::Crc32c(&data[0], data.size());
  InlineEncodeFixed32(&header_buf[4], msg_crc);

  // Then the CRC of the header
  uint32_t header_crc = crc::Crc32c(&header_buf, 8);
  InlineEncodeFixed32(&header_buf[8], header_crc);

  // Write the header to the file, followed by the batch data itself.
  RETURN_NOT_OK(writable_file_->Append(Slice(header_buf, sizeof(header_buf))));
  written_offset_ += sizeof(header_buf);

  RETURN_NOT_OK(writable_file_->Append(data));
  written_offset_ += data.size();

  return Status::OK();
}


void CreateBatchFromAllocatedOperations(const vector<consensus::ReplicateRefPtr>& msgs,
                                        gscoped_ptr<LogEntryBatchPB>* batch) {
  gscoped_ptr<LogEntryBatchPB> entry_batch(new LogEntryBatchPB);
  entry_batch->mutable_entry()->Reserve(msgs.size());
  for (size_t i = 0; i < msgs.size(); i++) {
    consensus::ReplicateMsg* msg = msgs[i]->get();
    LogEntryPB* entry_pb = entry_batch->add_entry();
    entry_pb->set_type(log::REPLICATE);
    entry_pb->set_allocated_replicate(msg);
  }
  batch->reset(entry_batch.release());
}

bool IsLogFileName(const string& fname) {
  if (HasPrefixString(fname, ".")) {
    // Hidden file or ./..
    VLOG(1) << "Ignoring hidden file: " << fname;
    return false;
  }

  if (HasSuffixString(fname, kTmpSuffix)) {
    LOG(WARNING) << "Ignoring tmp file: " << fname;
    return false;
  }

  vector<string> v = strings::Split(fname, "-");
  if (v.size() != 2 || v[0] != FsManager::kWalFileNamePrefix) {
    VLOG(1) << "Not a log file: " << fname;
    return false;
  }

  return true;
}

}  // namespace log
}  // namespace kudu
