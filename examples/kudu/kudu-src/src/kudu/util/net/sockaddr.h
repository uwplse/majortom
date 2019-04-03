// Copyright (c) 2013, Cloudera, inc.
// Confidential Cloudera Information: Covered by NDA.
#ifndef KUDU_UTIL_NET_SOCKADDR_H
#define KUDU_UTIL_NET_SOCKADDR_H

#include <netinet/in.h>
#include <iosfwd>
#include <string>
#include <tr1/functional_hash.h>

#include "kudu/util/status.h"

namespace kudu {

///
/// Represents a sockaddr.
///
/// Currently only IPv4 is implemented.  When IPv6 and UNIX domain are
/// implemented, this should become an abstract base class and those should be
/// multiple implementations.
///
class Sockaddr {
 public:
  Sockaddr();
  explicit Sockaddr(const struct sockaddr_in &addr);

  // Parse a string IP address of the form "A.B.C.D:port", storing the result
  // in this Sockaddr object. If no ':port' is specified, uses 'default_port'.
  // Note that this function will not handle resolving hostnames.
  //
  // Returns a bad Status if the input is malformed.
  Status ParseString(const std::string& s, uint16_t default_port);

  Sockaddr& operator=(const struct sockaddr_in &addr);

  bool operator==(const Sockaddr& other) const;

  // Compare the endpoints of two sockaddrs.
  // The port number is ignored in this comparison.
  bool operator<(const Sockaddr &rhs) const;

  uint32_t HashCode() const;

  std::string host() const;

  void set_port(int port);
  int port() const;
  const struct sockaddr_in& addr() const;
  std::string ToString() const;

  // Returns true if the address is 0.0.0.0
  bool IsWildcard() const;

  // Returns true if the address is 127.*.*.*
  bool IsAnyLocalAddress() const;

  // Does reverse DNS lookup of the address and stores it in hostname.
  Status LookupHostname(std::string* hostname) const;

  // the default auto-generated copy constructor is fine here
 private:
  struct sockaddr_in addr_;
};

} // namespace kudu

// Specialize std::tr1::hash for Sockaddr
namespace std { namespace tr1 {
template<>
struct hash<kudu::Sockaddr> {
  int operator()(const kudu::Sockaddr& addr) const {
    return addr.HashCode();
  }
};
} // namespace tr1
} // namespace std
#endif
