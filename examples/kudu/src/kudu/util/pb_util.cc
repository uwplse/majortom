// Copyright (c) 2013, Cloudera, inc.
// Confidential Cloudera Information: Covered by NDA.
// All rights reserved.
//
// Some portions copyright (C) 2008, Google, inc.
//
// Utilities for working with protobufs.
// Some of this code is cribbed from the protobuf source,
// but modified to work with kudu's 'faststring' instead of STL strings.

#include "kudu/util/pb_util.h"

#include <deque>
#include <string>
#include <tr1/memory>
#include <tr1/unordered_set>
#include <vector>

#include <boost/foreach.hpp>
#include <glog/logging.h>
#include <google/protobuf/descriptor.h>
#include <google/protobuf/descriptor.pb.h>
#include <google/protobuf/descriptor_database.h>
#include <google/protobuf/dynamic_message.h>
#include <google/protobuf/io/coded_stream.h>
#include <google/protobuf/io/zero_copy_stream.h>
#include <google/protobuf/io/zero_copy_stream_impl_lite.h>
#include <google/protobuf/message_lite.h>
#include <google/protobuf/message.h>

#include "kudu/gutil/bind.h"
#include "kudu/gutil/callback.h"
#include "kudu/gutil/map-util.h"
#include "kudu/gutil/strings/escaping.h"
#include "kudu/gutil/strings/fastmem.h"
#include "kudu/gutil/strings/substitute.h"
#include "kudu/util/coding.h"
#include "kudu/util/coding-inl.h"
#include "kudu/util/crc.h"
#include "kudu/util/debug/sanitizer_scopes.h"
#include "kudu/util/debug/trace_event.h"
#include "kudu/util/env.h"
#include "kudu/util/env_util.h"
#include "kudu/util/path_util.h"
#include "kudu/util/pb_util.pb.h"
#include "kudu/util/pb_util-internal.h"
#include "kudu/util/status.h"

using google::protobuf::Descriptor;
using google::protobuf::DescriptorPool;
using google::protobuf::DynamicMessageFactory;
using google::protobuf::FieldDescriptor;
using google::protobuf::FileDescriptor;
using google::protobuf::FileDescriptorProto;
using google::protobuf::FileDescriptorSet;
using google::protobuf::io::ArrayInputStream;
using google::protobuf::io::CodedInputStream;
using google::protobuf::Message;
using google::protobuf::MessageLite;
using google::protobuf::Reflection;
using google::protobuf::SimpleDescriptorDatabase;
using kudu::crc::Crc;
using kudu::pb_util::internal::SequentialFileFileInputStream;
using kudu::pb_util::internal::WritableFileOutputStream;
using std::deque;
using std::endl;
using std::string;
using std::tr1::shared_ptr;
using std::tr1::unordered_set;
using std::vector;
using strings::Substitute;
using strings::Utf8SafeCEscape;

static const char* const kTmpTemplateSuffix = ".tmp.XXXXXX";

// Protobuf container constants.
static const int kPBContainerVersion = 1;
static const char kPBContainerMagic[] = "kuducntr";
static const int kPBContainerMagicLen = 8;
static const int kPBContainerHeaderLen =
    // magic number + version
    kPBContainerMagicLen + sizeof(uint32_t);
static const int kPBContainerChecksumLen = sizeof(uint32_t);

COMPILE_ASSERT((arraysize(kPBContainerMagic) - 1) == kPBContainerMagicLen,
               kPBContainerMagic_does_not_match_expected_length);

namespace kudu {
namespace pb_util {

namespace {

// When serializing, we first compute the byte size, then serialize the message.
// If serialization produces a different number of bytes than expected, we
// call this function, which crashes.  The problem could be due to a bug in the
// protobuf implementation but is more likely caused by concurrent modification
// of the message.  This function attempts to distinguish between the two and
// provide a useful error message.
void ByteSizeConsistencyError(int byte_size_before_serialization,
                              int byte_size_after_serialization,
                              int bytes_produced_by_serialization) {
  CHECK_EQ(byte_size_before_serialization, byte_size_after_serialization)
      << "Protocol message was modified concurrently during serialization.";
  CHECK_EQ(bytes_produced_by_serialization, byte_size_before_serialization)
      << "Byte size calculation and serialization were inconsistent.  This "
         "may indicate a bug in protocol buffers or it may be caused by "
         "concurrent modification of the message.";
  LOG(FATAL) << "This shouldn't be called if all the sizes are equal.";
}

string InitializationErrorMessage(const char* action,
                                  const MessageLite& message) {
  // Note:  We want to avoid depending on strutil in the lite library, otherwise
  //   we'd use:
  //
  // return strings::Substitute(
  //   "Can't $0 message of type \"$1\" because it is missing required "
  //   "fields: $2",
  //   action, message.GetTypeName(),
  //   message.InitializationErrorString());

  string result;
  result += "Can't ";
  result += action;
  result += " message of type \"";
  result += message.GetTypeName();
  result += "\" because it is missing required fields: ";
  result += message.InitializationErrorString();
  return result;
}

} // anonymous namespace

bool AppendToString(const MessageLite &msg, faststring *output) {
  DCHECK(msg.IsInitialized()) << InitializationErrorMessage("serialize", msg);
  return AppendPartialToString(msg, output);
}

bool AppendPartialToString(const MessageLite &msg, faststring* output) {
  int old_size = output->size();
  int byte_size = msg.ByteSize();

  output->resize(old_size + byte_size);

  uint8* start = &((*output)[old_size]);
  uint8* end = msg.SerializeWithCachedSizesToArray(start);
  if (end - start != byte_size) {
    ByteSizeConsistencyError(byte_size, msg.ByteSize(), end - start);
  }
  return true;
}

bool SerializeToString(const MessageLite &msg, faststring *output) {
  output->clear();
  return AppendToString(msg, output);
}

bool ParseFromSequentialFile(MessageLite *msg, SequentialFile *rfile) {
  SequentialFileFileInputStream istream(rfile);
  return msg->ParseFromZeroCopyStream(&istream);
}

Status ParseFromArray(MessageLite* msg, const uint8_t* data, uint32_t length) {
  if (!msg->ParseFromArray(data, length)) {
    return Status::Corruption("Error parsing msg", InitializationErrorMessage("parse", *msg));
  }
  return Status::OK();
}

Status WritePBToPath(Env* env, const std::string& path,
                     const MessageLite& msg,
                     SyncMode sync) {
  const string tmp_template = path + kTmpTemplateSuffix;
  string tmp_path;

  gscoped_ptr<WritableFile> file;
  RETURN_NOT_OK(env->NewTempWritableFile(WritableFileOptions(), tmp_template, &tmp_path, &file));
  env_util::ScopedFileDeleter tmp_deleter(env, tmp_path);

  WritableFileOutputStream ostream(file.get());
  bool res = msg.SerializeToZeroCopyStream(&ostream);
  if (!res || !ostream.Flush()) {
    return Status::IOError("Unable to serialize PB to file");
  }

  if (sync == pb_util::SYNC) {
    RETURN_NOT_OK_PREPEND(file->Sync(), "Failed to Sync() " + tmp_path);
  }
  RETURN_NOT_OK_PREPEND(file->Close(), "Failed to Close() " + tmp_path);
  RETURN_NOT_OK_PREPEND(env->RenameFile(tmp_path, path), "Failed to rename tmp file to " + path);
  tmp_deleter.Cancel();
  if (sync == pb_util::SYNC) {
    RETURN_NOT_OK_PREPEND(env->SyncDir(DirName(path)), "Failed to SyncDir() parent of " + path);
  }
  return Status::OK();
}

Status ReadPBFromPath(Env* env, const std::string& path, MessageLite* msg) {
  shared_ptr<SequentialFile> rfile;
  RETURN_NOT_OK(env_util::OpenFileForSequential(env, path, &rfile));
  if (!ParseFromSequentialFile(msg, rfile.get())) {
    return Status::IOError("Unable to parse PB from path", path);
  }
  return Status::OK();
}

static void TruncateString(string* s, int max_len) {
  if (s->size() > max_len) {
    s->resize(max_len);
    s->append("<truncated>");
  }
}

void TruncateFields(Message* message, int max_len) {
  const Reflection* reflection = message->GetReflection();
  vector<const FieldDescriptor*> fields;
  reflection->ListFields(*message, &fields);
  BOOST_FOREACH(const FieldDescriptor* field, fields) {
    if (field->is_repeated()) {
      for (int i = 0; i < reflection->FieldSize(*message, field); i++) {
        switch (field->cpp_type()) {
          case FieldDescriptor::CPPTYPE_STRING: {
            const string& s_const = reflection->GetRepeatedStringReference(*message, field, i,
                                                                           NULL);
            TruncateString(const_cast<string*>(&s_const), max_len);
            break;
          }
          case FieldDescriptor::CPPTYPE_MESSAGE: {
            TruncateFields(reflection->MutableRepeatedMessage(message, field, i), max_len);
            break;
          }
          default:
            break;
        }
      }
    } else {
      switch (field->cpp_type()) {
        case FieldDescriptor::CPPTYPE_STRING: {
          const string& s_const = reflection->GetStringReference(*message, field, NULL);
          TruncateString(const_cast<string*>(&s_const), max_len);
          break;
        }
        case FieldDescriptor::CPPTYPE_MESSAGE: {
          TruncateFields(reflection->MutableMessage(message, field), max_len);
          break;
        }
        default:
          break;
      }
    }
  }
}

WritablePBContainerFile::WritablePBContainerFile(gscoped_ptr<WritableFile> writer)
  : closed_(false),
    writer_(writer.Pass()) {
}

WritablePBContainerFile::~WritablePBContainerFile() {
  WARN_NOT_OK(Close(), "Could not Close() when destroying file");
}

Status WritablePBContainerFile::Init(const Message& msg) {
  DCHECK(!closed_);

  faststring buf;
  buf.resize(kPBContainerHeaderLen);

  // Serialize the magic.
  strings::memcpy_inlined(buf.data(), kPBContainerMagic, kPBContainerMagicLen);
  size_t offset = kPBContainerMagicLen;

  // Serialize the version.
  InlineEncodeFixed32(buf.data() + offset, kPBContainerVersion);
  offset += sizeof(uint32_t);
  DCHECK_EQ(kPBContainerHeaderLen, offset)
    << "Serialized unexpected number of total bytes";

  // Serialize the supplemental header.
  ContainerSupHeaderPB sup_header;
  PopulateDescriptorSet(msg.GetDescriptor()->file(),
                        sup_header.mutable_protos());
  sup_header.set_pb_type(msg.GetTypeName());
  RETURN_NOT_OK_PREPEND(AppendMsgToBuffer(sup_header, &buf),
                        "Failed to prepare supplemental header for writing");

  // Write the serialized buffer to the file.
  RETURN_NOT_OK_PREPEND(writer_->Append(buf),
                        "Failed to Append() header to file");
  return Status::OK();
}

Status WritablePBContainerFile::Append(const Message& msg) {
  DCHECK(!closed_);

  faststring buf;
  RETURN_NOT_OK_PREPEND(AppendMsgToBuffer(msg, &buf),
                        "Failed to prepare buffer for writing");
  RETURN_NOT_OK_PREPEND(writer_->Append(buf), "Failed to Append() data to file");

  return Status::OK();
}

Status WritablePBContainerFile::Flush() {
  DCHECK(!closed_);

  // TODO: Flush just the dirty bytes.
  RETURN_NOT_OK_PREPEND(writer_->Flush(WritableFile::FLUSH_ASYNC), "Failed to Flush() file");

  return Status::OK();
}

Status WritablePBContainerFile::Sync() {
  DCHECK(!closed_);

  RETURN_NOT_OK_PREPEND(writer_->Sync(), "Failed to Sync() file");

  return Status::OK();
}

Status WritablePBContainerFile::Close() {
  if (!closed_) {
    closed_ = true;

    RETURN_NOT_OK_PREPEND(writer_->Close(), "Failed to Close() file");
  }

  return Status::OK();
}

Status WritablePBContainerFile::AppendMsgToBuffer(const Message& msg, faststring* buf) {
  DCHECK(msg.IsInitialized()) << InitializationErrorMessage("serialize", msg);
  int data_size = msg.ByteSize();
  uint64_t bufsize = sizeof(uint32_t) + data_size + kPBContainerChecksumLen;

  // Grow the buffer to hold the new data.
  size_t orig_size = buf->size();
  buf->resize(orig_size + bufsize);
  uint8_t* dst = buf->data() + orig_size;

  // Serialize the data size.
  InlineEncodeFixed32(dst, static_cast<uint32_t>(data_size));
  size_t offset = sizeof(uint32_t);

  // Serialize the data.
  if (PREDICT_FALSE(!msg.SerializeWithCachedSizesToArray(dst + offset))) {
    return Status::IOError("Failed to serialize PB to array");
  }
  offset += data_size;

  // Calculate and serialize the checksum.
  uint32_t checksum = crc::Crc32c(dst, offset);
  InlineEncodeFixed32(dst + offset, checksum);
  offset += kPBContainerChecksumLen;

  DCHECK_EQ(bufsize, offset) << "Serialized unexpected number of total bytes";
  return Status::OK();
}

void WritablePBContainerFile::PopulateDescriptorSet(
    const FileDescriptor* desc, FileDescriptorSet* output) {
  // Because we don't compile protobuf with TSAN enabled, copying the
  // static PB descriptors in this function ends up triggering a lot of
  // race reports. We suppress the reports, but TSAN still has to walk
  // the stack, etc, and this function becomes very slow. So, we ignore
  // TSAN here.
  debug::ScopedTSANIgnoreReadsAndWrites ignore_tsan;

  FileDescriptorSet all_descs;

  // Tracks all schemas that have been added to 'unemitted' at one point
  // or another. Is a superset of 'unemitted' and only ever grows.
  unordered_set<const FileDescriptor*> processed;

  // Tracks all remaining unemitted schemas.
  deque<const FileDescriptor*> unemitted;

  InsertOrDie(&processed, desc);
  unemitted.push_front(desc);
  while (!unemitted.empty()) {
    const FileDescriptor* proto = unemitted.front();

    // The current schema is emitted iff we've processed (i.e. emitted) all
    // of its dependencies.
    bool emit = true;
    for (int i = 0; i < proto->dependency_count(); i++) {
      const FileDescriptor* dep = proto->dependency(i);
      if (InsertIfNotPresent(&processed, dep)) {
        unemitted.push_front(dep);
        emit = false;
      }
    }
    if (emit) {
      unemitted.pop_front();
      proto->CopyTo(all_descs.mutable_file()->Add());
    }
  }
  all_descs.Swap(output);
}

ReadablePBContainerFile::ReadablePBContainerFile(gscoped_ptr<RandomAccessFile> reader)
  : offset_(0),
    reader_(reader.Pass()) {
}

ReadablePBContainerFile::~ReadablePBContainerFile() {
  WARN_NOT_OK(Close(), "Could not Close() when destroying file");
}

Status ReadablePBContainerFile::Init() {
  // Read header data.
  Slice header;
  gscoped_ptr<uint8_t[]> scratch;
  RETURN_NOT_OK_PREPEND(ValidateAndRead(kPBContainerHeaderLen, EOF_NOT_OK, &header, &scratch),
                        Substitute("Could not read header for proto container file $0",
                                   reader_->filename()));

  // Validate magic number.
  if (PREDICT_FALSE(!strings::memeq(kPBContainerMagic, header.data(), kPBContainerMagicLen))) {
    string file_magic(reinterpret_cast<const char*>(header.data()), kPBContainerMagicLen);
    return Status::Corruption("Invalid magic number",
                              Substitute("Expected: $0, found: $1",
                                         Utf8SafeCEscape(kPBContainerMagic),
                                         Utf8SafeCEscape(file_magic)));
  }

  // Validate container file version.
  uint32_t version = DecodeFixed32(header.data() + kPBContainerMagicLen);
  if (PREDICT_FALSE(version != kPBContainerVersion)) {
    // We only support version 1.
    return Status::NotSupported(
        Substitute("Protobuf container has version $0, we only support version $1",
                   version, kPBContainerVersion));
  }

  // Read the supplemental header.
  ContainerSupHeaderPB sup_header;
  RETURN_NOT_OK_PREPEND(ReadNextPB(&sup_header), Substitute(
      "Could not read supplemental header from proto container file $0",
      reader_->filename()));
  protos_.reset(sup_header.release_protos());
  pb_type_ = sup_header.pb_type();

  return Status::OK();
}

Status ReadablePBContainerFile::ReadNextPB(Message* msg) {
  VLOG(1) << "Reading PB from offset $0 " << offset_;

  // Read the size from the file. EOF here is acceptable: it means we're
  // out of PB entries.
  Slice size;
  gscoped_ptr<uint8_t[]> size_scratch;
  RETURN_NOT_OK_PREPEND(ValidateAndRead(sizeof(uint32_t), EOF_OK, &size, &size_scratch),
                        Substitute("Could not read data size from proto container file $0",
                                   reader_->filename()));
  uint32_t data_size = DecodeFixed32(size.data());

  // Read body into buffer for checksum & parsing.
  Slice body;
  gscoped_ptr<uint8_t[]> body_scratch;
  RETURN_NOT_OK_PREPEND(ValidateAndRead(data_size, EOF_NOT_OK, &body, &body_scratch),
                        Substitute("Could not read body from proto container file $0",
                                   reader_->filename()));

  // Read checksum.
  uint32_t expected_checksum = 0;
  {
    Slice encoded_checksum;
    gscoped_ptr<uint8_t[]> encoded_checksum_scratch;
    RETURN_NOT_OK_PREPEND(ValidateAndRead(kPBContainerChecksumLen, EOF_NOT_OK,
                                          &encoded_checksum, &encoded_checksum_scratch),
                          Substitute("Could not read checksum from proto container file $0",
                                     reader_->filename()));
    expected_checksum = DecodeFixed32(encoded_checksum.data());
  }

  // Validate CRC32C checksum.
  Crc* crc32c = crc::GetCrc32cInstance();
  uint64_t actual_checksum = 0;
  // Compute a rolling checksum over the two byte arrays (size, body).
  crc32c->Compute(size.data(), size.size(), &actual_checksum);
  crc32c->Compute(body.data(), body.size(), &actual_checksum);
  if (PREDICT_FALSE(actual_checksum != expected_checksum)) {
    return Status::Corruption(Substitute("Incorrect checksum of file $0: actually $1, expected $2",
                                         reader_->filename(), actual_checksum, expected_checksum));
  }

  // The checksum is correct. Time to decode the body.
  //
  // We could compare pb_type_ against msg.GetTypeName(), but:
  // 1. pb_type_ is not available when reading the supplemental header,
  // 2. ParseFromArray() should fail if the data cannot be parsed into the
  //    provided message type.

  // To permit parsing of very large PB messages, we must use parse through a
  // CodedInputStream and bump the byte limit. The SetTotalBytesLimit() docs
  // say that 512MB is the shortest theoretical message length that may produce
  // integer overflow warnings, so that's what we'll use.
  ArrayInputStream ais(body.data(), body.size());
  CodedInputStream cis(&ais);
  cis.SetTotalBytesLimit(512 * 1024 * 1024, -1);
  if (PREDICT_FALSE(!msg->ParseFromCodedStream(&cis))) {
    return Status::IOError("Unable to parse PB from path", reader_->filename());
  }

  return Status::OK();
}

Status ReadablePBContainerFile::Dump(ostream* os, bool oneline) {
  // Use the embedded protobuf information from the container file to
  // create the appropriate kind of protobuf Message.
  //
  // Loading the schemas into a DescriptorDatabase (and not directly into
  // a DescriptorPool) defers resolution until FindMessageTypeByName()
  // below, allowing for schemas to be loaded in any order.
  SimpleDescriptorDatabase db;
  for (int i = 0; i < protos()->file_size(); i++) {
    if (!db.Add(protos()->file(i))) {
      return Status::Corruption("Descriptor not loaded", Substitute(
          "Could not load descriptor for PB type $0 referenced in container file",
          pb_type()));
    }
  }
  DescriptorPool pool(&db);
  const Descriptor* desc = pool.FindMessageTypeByName(pb_type());
  if (!desc) {
    return Status::NotFound("Descriptor not found", Substitute(
        "Could not find descriptor for PB type $0 referenced in container file",
        pb_type()));
  }
  DynamicMessageFactory factory;
  const Message* prototype = factory.GetPrototype(desc);
  if (!prototype) {
    return Status::NotSupported("Descriptor not supported", Substitute(
        "Descriptor $0 referenced in container file not supported",
        pb_type()));
  }
  gscoped_ptr<Message> msg(prototype->New());

  // Dump each message in the container file.
  int count = 0;
  Status s;
  for (s = ReadNextPB(msg.get());
      s.ok();
      s = ReadNextPB(msg.get())) {
    if (oneline) {
      *os << count++ << "\t" << msg->ShortDebugString() << endl;
    } else {
      *os << "Message " << count << endl;
      *os << "-------" << endl;
      *os << msg->DebugString() << endl;
      count++;
    }
  }
  return s.IsEndOfFile() ? s.OK() : s;
}

Status ReadablePBContainerFile::Close() {
  gscoped_ptr<RandomAccessFile> deleter;
  deleter.swap(reader_);
  return Status::OK();
}

Status ReadablePBContainerFile::ValidateAndRead(size_t length, EofOK eofOK,
                                                Slice* result, gscoped_ptr<uint8_t[]>* scratch) {
  // Validate the read length using the file size.
  uint64_t file_size;
  RETURN_NOT_OK(reader_->Size(&file_size));
  if (offset_ + length > file_size) {
    switch (eofOK) {
      case EOF_OK:
        return Status::EndOfFile("Reached end of file");
      case EOF_NOT_OK:
        return Status::Corruption("File size not large enough to be valid",
                                  Substitute("Proto container file $0: "
                                      "tried to read $0 bytes at offset "
                                      "$1 but file size is only $2",
                                      reader_->filename(), length,
                                      offset_, file_size));
      default:
        LOG(FATAL) << "Unknown value for eofOK: " << eofOK;
    }
  }

  // Perform the read.
  Slice s;
  gscoped_ptr<uint8_t[]> local_scratch(new uint8_t[length]);
  RETURN_NOT_OK(reader_->Read(offset_, length, &s, local_scratch.get()));

  // Sanity check the result.
  if (PREDICT_FALSE(s.size() < length)) {
    return Status::Corruption("Unexpected short read", Substitute(
        "Proto container file $0: tried to read $1 bytes; got $2 bytes",
        reader_->filename(), length, s.size()));
  }

  *result = s;
  scratch->swap(local_scratch);
  offset_ += s.size();
  return Status::OK();
}


Status ReadPBContainerFromPath(Env* env, const std::string& path, Message* msg) {
  gscoped_ptr<RandomAccessFile> file;
  RETURN_NOT_OK(env->NewRandomAccessFile(path, &file));

  ReadablePBContainerFile pb_file(file.Pass());
  RETURN_NOT_OK(pb_file.Init());
  RETURN_NOT_OK(pb_file.ReadNextPB(msg));
  return pb_file.Close();
}

Status WritePBContainerToPath(Env* env, const std::string& path,
                              const Message& msg,
                              CreateMode create,
                              SyncMode sync) {
  TRACE_EVENT2("io", "WritePBContainerToPath",
               "path", path,
               "msg_type", msg.GetTypeName());

  if (create == NO_OVERWRITE && env->FileExists(path)) {
    return Status::AlreadyPresent(Substitute("File $0 already exists", path));
  }

  const string tmp_template = path + kTmpTemplateSuffix;
  string tmp_path;

  gscoped_ptr<WritableFile> file;
  RETURN_NOT_OK(env->NewTempWritableFile(WritableFileOptions(), tmp_template, &tmp_path, &file));
  env_util::ScopedFileDeleter tmp_deleter(env, tmp_path);

  WritablePBContainerFile pb_file(file.Pass());
  RETURN_NOT_OK(pb_file.Init(msg));
  RETURN_NOT_OK(pb_file.Append(msg));
  if (sync == pb_util::SYNC) {
    RETURN_NOT_OK(pb_file.Sync());
  }
  RETURN_NOT_OK(pb_file.Close());
  RETURN_NOT_OK_PREPEND(env->RenameFile(tmp_path, path),
                        "Failed to rename tmp file to " + path);
  tmp_deleter.Cancel();
  if (sync == pb_util::SYNC) {
    RETURN_NOT_OK_PREPEND(env->SyncDir(DirName(path)),
                          "Failed to SyncDir() parent of " + path);
  }
  return Status::OK();
}

} // namespace pb_util
} // namespace kudu
