// Copyright (c) 2014, Cloudera, inc.
// Confidential Cloudera Information: Covered by NDA.
package org.kududb.client;

import org.kududb.annotations.InterfaceAudience;
import org.kududb.annotations.InterfaceStability;

@InterfaceAudience.Public
@InterfaceStability.Evolving
public class DeleteTableResponse extends KuduRpcResponse {

  /**
   * @param ellapsedMillis Time in milliseconds since RPC creation to now.
   */
  DeleteTableResponse(long ellapsedMillis, String tsUUID) {
    super(ellapsedMillis, tsUUID);
  }
}
