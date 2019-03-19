// Copyright (c) 2013, Cloudera, inc.
// Confidential Cloudera Information: Covered by NDA.
// All rights reserved.
//
// Utilities for dealing with protocol buffers.
// These are mostly just functions similar to what are found in the protobuf
// library itself, but using kudu::faststring instances instead of STL strings.
#ifndef KUDU_UTIL_PB_UTIL_H
#define KUDU_UTIL_PB_UTIL_H

#include <string>

#include <gtest/gtest_prod.h>

#include "kudu/gutil/gscoped_ptr.h"
#include "kudu/util/faststring.h"

namespace google {
namespace protobuf {
class FileDescriptor;
class FileDescriptorSet;
class MessageLite;
class Message;
}
}

namespace kudu {

class Env;
class RandomAccessFile;
class SequentialFile;
class Slice;
class Status;
class WritableFile;

namespace pb_util {

using google::protobuf::MessageLite;

enum SyncMode {
  SYNC,
  NO_SYNC
};

enum CreateMode {
  OVERWRITE,
  NO_OVERWRITE
};

// See MessageLite::AppendToString
bool AppendToString(const MessageLite &msg, faststring *output);

// See MessageLite::AppendPartialToString
bool AppendPartialToString(const MessageLite &msg, faststring *output);

// See MessageLite::SerializeToString.
bool SerializeToString(const MessageLite &msg, faststring *output);

// See MessageLite::ParseFromZeroCopyStream
// TODO: change this to return Status - differentiate IO error from bad PB
bool ParseFromSequentialFile(MessageLite *msg, SequentialFile *rfile);

// Similar to MessageLite::ParseFromArray, with the difference that it returns
// Status::Corruption() if the message could not be parsed.
Status ParseFromArray(MessageLite* msg, const uint8_t* data, uint32_t length);

// Load a protobuf from the given path.
Status ReadPBFromPath(Env* env, const std::string& path, MessageLite* msg);

// Serialize a protobuf to the given path.
//
// If SyncMode SYNC is provided, ensures the changes are made durable.
Status WritePBToPath(Env* env, const std::string& path, const MessageLite& msg, SyncMode sync);

// Truncate any 'bytes' or 'string' fields of this message to max_len.
// The text "<truncated>" is appended to any such truncated fields.
void TruncateFields(google::protobuf::Message* message, int max_len);

// A protobuf "container" has the following format (all integers in
// little-endian byte order):
//
//
//
// magic number: 8 byte string identifying the file format.
//
//               Included so that we have a minimal guarantee that this file is
//               of the type we expect and that we are not just reading garbage.
//
// container_version: 4 byte unsigned integer indicating the "version" of the
//                    container format. Must be set to 1 at this time.
//
//                    Included so that this file format may be extended at some
//                    later date while maintaining backwards compatibility.
//
//
// The remaining container fields are repeated (in a group) for each protobuf message.
//
//
// data size: 4 byte unsigned integer indicating the size of the encoded data.
//
//            Included because PB messages aren't self-delimiting, and thus
//            writing a stream of messages to the same file requires
//            delimiting each with its size.
//
//            See https://developers.google.com/protocol-buffers/docs/techniques?hl=zh-cn#streaming
//            for more details.
//
// data: "size" bytes of protobuf data encoded according to the schema.
//
//       Our payload.
//
// checksum: 4 byte unsigned integer containing the CRC32C checksum of "data".
//
//           Included to ensure validity of the data on-disk.
//
// Every container must have at least one protobuf message: the
// supplemental header. It includes additional container-level information.
// See pb_util.proto for details. As a containerized PB message, the header
// is protected by a CRC32C checksum like any other message.
//
//
// It is worth describing the kinds of errors that can be detected by the
// protobuf container and the kinds that cannot.
//
// The checksums in the container are independent, not rolling. As such,
// they won't detect the disappearance or reordering of entire protobuf
// messages, which can happen if a range of the file is collapsed (see
// man fallocate(2)) or if the file is otherwise manually manipulated.
// Moreover, the checksums do not protect against corruption in the data
// size fields, though that is mitigated by validating each data size
// against the remaining number of bytes in the container.
//
// Additionally, the container does not include footers or periodic
// checkpoints. As such, it will not detect if entire protobuf messages
// are truncated.
//
// That said, all corruption or truncation of the magic number or the
// container version will be detected, as will most corruption/truncation
// of the data size, data, and checksum (subject to CRC32 limitations).
//
// These tradeoffs in error detection are reasonable given the failure
// environment that Kudu operates within. We tolerate failures such as
// "kill -9" of the Kudu process, machine power loss, or fsync/fdatasync
// failure, but not failures like runaway processes mangling data files
// in arbitrary ways or attackers crafting malicious data files.
//
// The one kind of failure that clients must handle is truncation of entire
// protobuf messages (see above). The protobuf container will not detect
// these failures, so clients must tolerate them in some way.
//
// For further reading on what files might look like following a normal
// filesystem failure, see:
//
// https://www.usenix.org/system/files/conference/osdi14/osdi14-paper-pillai.pdf

// Protobuf container file opened for writing.
//
// Can be built around an existing file or a completely new file.
//
// Not thread-safe.
class WritablePBContainerFile {
 public:

  // Initializes the class instance; writer must be open.
  explicit WritablePBContainerFile(gscoped_ptr<WritableFile> writer);

  // Closes the container if not already closed.
  ~WritablePBContainerFile();

  // Writes the header information to the container.
  //
  // 'msg' need not be populated; its type is used to "lock" the container
  // to a particular protobuf message type in Append().
  Status Init(const google::protobuf::Message& msg);

  // Writes a protobuf message to the container, beginning with its size
  // and ending with its CRC32 checksum.
  Status Append(const google::protobuf::Message& msg);

  // Asynchronously flushes all dirty container data to the filesystem.
  Status Flush();

  // Synchronizes all dirty container data to the filesystem.
  //
  // Note: the parent directory is _not_ synchronized. Because the
  // container file was provided during construction, we don't know whether
  // it was created or reopened, and parent directory synchronization is
  // only needed in the former case.
  Status Sync();

  // Closes the container.
  Status Close();

 private:
  FRIEND_TEST(TestPBUtil, TestPopulateDescriptorSet);

  // Write the protobuf schemas belonging to 'desc' and all of its
  // dependencies to 'output'.
  //
  // Schemas are written in dependency order (i.e. if A depends on B which
  // depends on C, the order is C, B, A).
  static void PopulateDescriptorSet(const google::protobuf::FileDescriptor* desc,
                                    google::protobuf::FileDescriptorSet* output);

  // Serialize the contents of 'msg' into 'buf' along with additional metadata
  // to aid in deserialization.
  Status AppendMsgToBuffer(const google::protobuf::Message& msg, faststring* buf);

  bool closed_;

  gscoped_ptr<WritableFile> writer_;
};

// Protobuf container file opened for reading.
//
// Can be built around a file with existing contents or an empty file (in
// which case it's safe to interleave with WritablePBContainerFile).
class ReadablePBContainerFile {
 public:

  // Initializes the class instance; reader must be open.
  explicit ReadablePBContainerFile(gscoped_ptr<RandomAccessFile> reader);

  // Closes the file if not already closed.
  ~ReadablePBContainerFile();

  // Reads the header information from the container and validates it.
  Status Init();

  // Reads a protobuf message from the container, validating its size and
  // data using a CRC32 checksum.
  Status ReadNextPB(google::protobuf::Message* msg);

  // Dumps any unread protobuf messages in the container to 'os'. Each
  // message's DebugString() method is invoked to produce its textual form.
  //
  // If 'oneline' is true, prints each message on a single line.
  Status Dump(std::ostream* os, bool oneline);

  // Closes the container.
  Status Close();

  // Expected PB type and schema for each message to be read.
  //
  // Only valid after a successful call to Init().
  const std::string& pb_type() const { return pb_type_; }
  const google::protobuf::FileDescriptorSet* protos() const {
    return protos_.get();
  }

 private:
  enum EofOK {
    EOF_OK,
    EOF_NOT_OK
  };

  // Reads exactly 'length' bytes from the container file into 'scratch',
  // validating the correctness of the read both before and after and
  // returning a slice of the bytes in 'result'.
  //
  // If 'eofOK' is EOF_OK, an EOF is returned as-is. Otherwise, it is
  // considered to be an invalid short read and returned as an error.
  Status ValidateAndRead(size_t length, EofOK eofOK,
                         Slice* result, gscoped_ptr<uint8_t[]>* scratch);

  size_t offset_;

  // The fully-qualified PB type name of the messages in the container.
  std::string pb_type_;

  // Wrapped in a gscoped_ptr so that clients need not include PB headers.
  gscoped_ptr<google::protobuf::FileDescriptorSet> protos_;

  gscoped_ptr<RandomAccessFile> reader_;
};

// Convenience functions for protobuf containers holding just one record.

// Load a "containerized" protobuf from the given path.
// If the file does not exist, returns Status::NotFound(). Otherwise, may
// return other Status error codes such as Status::IOError.
Status ReadPBContainerFromPath(Env* env, const std::string& path,
                               google::protobuf::Message* msg);

// Serialize a "containerized" protobuf to the given path.
//
// If create == NO_OVERWRITE and 'path' already exists, the function will fail.
// If sync == SYNC, the newly created file will be fsynced before returning.
Status WritePBContainerToPath(Env* env, const std::string& path,
                              const google::protobuf::Message& msg,
                              CreateMode create,
                              SyncMode sync);

} // namespace pb_util
} // namespace kudu
#endif
