/*
 * Copyright (c) 2014 Cloudera, Inc.
 * Confidential Cloudera Information: Covered by NDA.
 */
package org.kududb.client;

import java.util.List;

import com.google.common.collect.Lists;
import com.google.common.collect.ImmutableList;
import org.kududb.annotations.InterfaceAudience;
import org.kududb.annotations.InterfaceStability;
import org.kududb.consensus.Metadata.RaftPeerPB.Role;
import org.kududb.master.Master.TabletLocationsPB;
import org.kududb.master.Master.TabletLocationsPB.ReplicaPB;

/**
 * Information about the locations of tablets in a Kudu table.
 * This should be treated as immutable data (it does not reflect
 * any updates the client may have heard since being constructed).
 */
@InterfaceAudience.Public
@InterfaceStability.Evolving
public class LocatedTablet {
  private final Partition partition;
  private final byte[] tabletId;

  private final List<Replica> replicas;

  LocatedTablet(TabletLocationsPB pb) {
    this.partition = ProtobufHelper.pbToPartition(pb.getPartition());
    this.tabletId = pb.getTabletId().toByteArray();

    List<Replica> reps = Lists.newArrayList();
    for (ReplicaPB repPb : pb.getReplicasList()) {
      reps.add(new Replica(repPb));
    }
    this.replicas = ImmutableList.copyOf(reps);
  }

  public List<Replica> getReplicas() {
    return replicas;
  }

  public Partition getPartition() {
    return partition;
  }

  /**
   * DEPRECATED: use {@link #getPartition()}
   */
  @Deprecated
  public byte[] getStartKey() {
    return getPartition().getPartitionKeyStart();
  }

  /**
   * DEPRECATED: use {@link #getPartition()}
   */
  @Deprecated()
  public byte[] getEndKey() {
    return getPartition().getPartitionKeyEnd();
  }

  public byte[] getTabletId() {
    return tabletId;
  }

  /**
   * Return the current leader, or null if there is none.
   */
  public Replica getLeaderReplica() {
    return getOneOfRoleOrNull(Role.LEADER);
  }

  /**
   * Return the first occurrence for the given role, or null if there is none.
   */
  private Replica getOneOfRoleOrNull(Role role) {
    for (Replica r : replicas) {
      if (r.getRole() == role.toString()) return r;
    }
    return null;
  }

  @Override
  public String toString() {
    return Bytes.pretty(tabletId) + " " + partition.toString();
  }

  /**
   * One of the replicas of the tablet.
   */
  public static class Replica {
    private final ReplicaPB pb;

    private Replica(ReplicaPB pb) {
      this.pb = pb;
    }

    public String getRpcHost() {
      if (pb.getTsInfo().getRpcAddressesList().isEmpty()) {
        return null;
      }
      return pb.getTsInfo().getRpcAddressesList().get(0).getHost();
    }

    public Integer getRpcPort() {
      if (pb.getTsInfo().getRpcAddressesList().isEmpty()) {
        return null;
      }
      return pb.getTsInfo().getRpcAddressesList().get(0).getPort();
    }

    public String getRole() {
      return pb.getRole().toString();
    }

    public String toString() {
      return pb.toString();
    }
  }

};
