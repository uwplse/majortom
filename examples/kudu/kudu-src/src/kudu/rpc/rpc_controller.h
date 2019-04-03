// Copyright (c) 2013, Cloudera, inc.
// Confidential Cloudera Information: Covered by NDA.
// All rights reserved.
#ifndef KUDU_RPC_RPC_CONTROLLER_H
#define KUDU_RPC_RPC_CONTROLLER_H

#include <glog/logging.h>
#include <tr1/memory>

#include "kudu/gutil/macros.h"
#include "kudu/util/locks.h"
#include "kudu/util/monotime.h"
#include "kudu/util/status.h"

namespace kudu {

namespace rpc {

class ErrorStatusPB;
class OutboundCall;

// Controller for managing properties of a single RPC call, on the client side.
//
// An RpcController maps to exactly one call and is not thread-safe. The client
// may use this class prior to sending an RPC in order to set properties such
// as the call's timeout.
//
// After the call has been sent (e.g using Proxy::AsyncRequest()) the user
// may invoke methods on the RpcController object in order to probe the status
// of the call.
class RpcController {
 public:
  RpcController();
  ~RpcController();

  // Reset this controller so it may be used with another call.
  void Reset();

  // Return true if the call has finished.
  // A call is finished if the server has responded, or if the call
  // has timed out.
  bool finished() const;

  // Return the current status of a call.
  //
  // A call is "OK" status until it finishes, at which point it may
  // either remain in "OK" status (if the call was successful), or
  // change to an error status. Error status indicates that there was
  // some RPC-layer issue with making the call, for example, one of:
  //
  // * failed to establish a connection to the server
  // * the server was too busy to handle the request
  // * the server was unable to interpret the request (eg due to a version
  //   mismatch)
  // * a network error occurred which caused the connection to be torn
  //   down
  // * the call timed out
  Status status() const;

  // If status() returns a RemoteError object, then this function returns
  // the error response provided by the server. Service implementors may
  // use protobuf Extensions to add application-specific data to this PB.
  //
  // If Status was not a RemoteError, this returns NULL.
  // The returned pointer is only valid as long as the controller object.
  const ErrorStatusPB* error_response() const;

  // Set the timeout for the call to be made with this RPC controller.
  //
  // The configured timeout applies to the entire time period between
  // the AsyncRequest() method call and getting a response. For example,
  // if it takes too long to establish a connection to the remote host,
  // or to DNS-resolve the remote host, those will be accounted as part
  // of the timeout period.
  //
  // Timeouts must be set prior to making the request -- the timeout may
  // not currently be adjusted for an already-sent call.
  //
  // Using an uninitialized timeout will result in a call which never
  // times out (not recommended!)
  void set_timeout(const MonoDelta& timeout);

  // Like a timeout, but based on a fixed point in time instead of a delta.
  //
  // Using an uninitialized deadline means the call won't time out.
  void set_deadline(const MonoTime& deadline);

  // Return the configured timeout.
  MonoDelta timeout() const;

  // Fills the 'sidecar' parameter with the slice pointing to the i-th
  // sidecar upon success.
  //
  // Should only be called if the call's finished, but the controller has not
  // been Reset().
  //
  // May fail if index is invalid.
  Status GetSidecar(int idx, Slice* sidecar) const;

 private:
  friend class OutboundCall;
  friend class Proxy;

  MonoDelta timeout_;

  mutable simple_spinlock lock_;

  // Once the call is sent, it is tracked here.
  std::tr1::shared_ptr<OutboundCall> call_;

  DISALLOW_COPY_AND_ASSIGN(RpcController);
};

} // namespace rpc
} // namespace kudu
#endif
