// Copyright (c) 2013, Cloudera, inc.
// Confidential Cloudera Information: Covered by NDA.
// All rights reserved.

#include "kudu/rpc/negotiation.h"

#include <sys/time.h>
#include <poll.h>

#include <string>

#include <glog/logging.h>

#include "kudu/gutil/stringprintf.h"
#include "kudu/gutil/strings/substitute.h"
#include "kudu/rpc/blocking_ops.h"
#include "kudu/rpc/connection.h"
#include "kudu/rpc/reactor.h"
#include "kudu/rpc/rpc_header.pb.h"
#include "kudu/rpc/sasl_client.h"
#include "kudu/rpc/sasl_common.h"
#include "kudu/rpc/sasl_server.h"
#include "kudu/util/status.h"

namespace kudu {
namespace rpc {

using std::tr1::shared_ptr;
using strings::Substitute;

// Client: Send ConnectionContextPB message based on information stored in the Connection object.
static Status SendConnectionContext(Connection* conn, const MonoTime& deadline) {
  RequestHeader header;
  header.set_call_id(kConnectionContextCallId);

  ConnectionContextPB conn_context;
  conn_context.mutable_user_info()->set_effective_user(conn->user_credentials().effective_user());
  conn_context.mutable_user_info()->set_real_user(conn->user_credentials().real_user());

  return SendFramedMessageBlocking(conn->socket(), header, conn_context, deadline);
}

// Server: Receive ConnectionContextPB message and update the corresponding fields in the
// associated Connection object. Perform validation against SASL-negotiated information
// as needed.
static Status RecvConnectionContext(Connection* conn, const MonoTime& deadline) {
  faststring recv_buf(1024); // Should be plenty for a ConnectionContextPB message.
  RequestHeader header;
  Slice param_buf;
  RETURN_NOT_OK(ReceiveFramedMessageBlocking(conn->socket(), &recv_buf,
                                             &header, &param_buf, deadline));
  DCHECK(header.IsInitialized());

  if (header.call_id() != kConnectionContextCallId) {
    return Status::IllegalState("Expected ConnectionContext callid, received",
        Substitute("$0", header.call_id()));
  }

  ConnectionContextPB conn_context;
  if (!conn_context.ParseFromArray(param_buf.data(), param_buf.size())) {
    return Status::InvalidArgument("Invalid ConnectionContextPB message, missing fields",
        conn_context.InitializationErrorString());
  }

  // Update the fields of our Connection object from the ConnectionContextPB.
  if (conn_context.has_user_info()) {
    // Validate real user against SASL impl.
    if (conn->sasl_server().negotiated_mechanism() == SaslMechanism::PLAIN) {
      if (conn->sasl_server().plain_auth_user() != conn_context.user_info().real_user()) {
        return Status::NotAuthorized(
            "ConnectionContextPB specified different real user than sent in SASL negotiation",
            StringPrintf("\"%s\" vs. \"%s\"",
                conn_context.user_info().real_user().c_str(),
                conn->sasl_server().plain_auth_user().c_str()));
      }
    }
    conn->mutable_user_credentials()->set_real_user(conn_context.user_info().real_user());

    // TODO: Validate effective user when we implement impersonation.
    if (conn_context.user_info().has_effective_user()) {
      conn->mutable_user_credentials()->set_effective_user(
        conn_context.user_info().effective_user());
    }
  }
  return Status::OK();
}

// Wait for the client connection to be established and become ready for writing.
static Status WaitForClientConnect(Connection* conn, const MonoTime& deadline) {
  int fd = conn->socket()->GetFd();
  struct pollfd poll_fd;
  poll_fd.fd = fd;
  poll_fd.events = POLLOUT;
  poll_fd.revents = 0;

  MonoTime now;
  MonoDelta remaining;
  struct timespec ts;
  while (true) {
    now = MonoTime::Now(MonoTime::FINE);
    remaining = deadline.GetDeltaSince(now);
    DVLOG(4) << "Client waiting to connect for negotiation, time remaining until timeout deadline: "
             << remaining.ToString();
    if (PREDICT_FALSE(remaining.ToNanoseconds() <= 0)) {
      return Status::TimedOut("Timeout exceeded waiting to connect");
    }
    remaining.ToTimeSpec(&ts);
    int ready = ppoll(&poll_fd, 1, &ts, NULL);
    if (ready == -1) {
      int err = errno;
      if (err == EINTR) {
        // We were interrupted by a signal, let's go again.
        continue;
      } else {
        return Status::NetworkError("Error from ppoll() while waiting to connect",
            ErrnoToString(err), err);
      }
    } else if (ready == 0) {
      // Timeout exceeded. Loop back to the top to our impending doom.
      continue;
    } else {
      // Success.
      break;
    }
  }

  // Connect finished, but this doesn't mean that we connected successfully.
  // Check the socket for an error.
  int so_error = 0;
  socklen_t socklen = sizeof(so_error);
  int rc = getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_error, &socklen);
  if (rc != 0) {
    return Status::NetworkError("Unable to check connected socket for errors",
                                ErrnoToString(errno),
                                errno);
  }
  if (so_error != 0) {
    return Status::NetworkError("connect", ErrnoToString(so_error), so_error);
  }

  return Status::OK();
}

// Disable / reset socket timeouts.
static Status DisableSocketTimeouts(Connection* conn) {
  RETURN_NOT_OK(conn->socket()->SetSendTimeout(MonoDelta::FromNanoseconds(0L)));
  RETURN_NOT_OK(conn->socket()->SetRecvTimeout(MonoDelta::FromNanoseconds(0L)));
  return Status::OK();
}

// Perform client negotiation. We don't LOG() anything, we leave that to our caller.
static Status DoClientNegotiation(Connection* conn,
                                  const MonoTime& deadline) {
  RETURN_NOT_OK(WaitForClientConnect(conn, deadline));
  RETURN_NOT_OK(conn->SetNonBlocking(false));
  RETURN_NOT_OK(conn->InitSaslClient());
  conn->sasl_client().set_deadline(deadline);
  RETURN_NOT_OK(conn->sasl_client().Negotiate());
  RETURN_NOT_OK(SendConnectionContext(conn, deadline));
  RETURN_NOT_OK(DisableSocketTimeouts(conn));

  return Status::OK();
}

// Perform server negotiation. We don't LOG() anything, we leave that to our caller.
static Status DoServerNegotiation(Connection* conn,
                                  const MonoTime& deadline) {
  RETURN_NOT_OK(conn->SetNonBlocking(false));
  RETURN_NOT_OK(conn->InitSaslServer());
  conn->sasl_server().set_deadline(deadline);
  RETURN_NOT_OK(conn->sasl_server().Negotiate());
  RETURN_NOT_OK(RecvConnectionContext(conn, deadline));
  RETURN_NOT_OK(DisableSocketTimeouts(conn));

  return Status::OK();
}

// Perform negotiation for a connection (either server or client)
void Negotiation::RunNegotiation(const scoped_refptr<Connection>& conn,
                                 const MonoTime& deadline) {
  Status s;
  if (conn->direction() == Connection::SERVER) {
    s = DoServerNegotiation(conn.get(), deadline);
  } else {
    s = DoClientNegotiation(conn.get(), deadline);
  }

  if (PREDICT_FALSE(!s.ok())) {
    string msg = Substitute("$0 connection negotiation failed: $1",
                            conn->direction() == Connection::SERVER ? "Server" : "Client",
                            conn->ToString());
    s = s.CloneAndPrepend(msg);
  }
  conn->CompleteNegotiation(s);
}


} // namespace rpc
} // namespace kudu
