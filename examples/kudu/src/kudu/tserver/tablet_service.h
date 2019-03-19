// Copyright (c) 2013, Cloudera, inc.
// Confidential Cloudera Information: Covered by NDA.
#ifndef KUDU_TSERVER_TABLET_SERVICE_H
#define KUDU_TSERVER_TABLET_SERVICE_H

#include <string>
#include <tr1/memory>
#include <vector>

#include "kudu/gutil/ref_counted.h"
#include "kudu/tserver/tserver_service.service.h"
#include "kudu/tserver/tserver_admin.service.h"
#include "kudu/consensus/consensus.service.h"

namespace kudu {
class RowwiseIterator;
class Schema;
class Status;
class Timestamp;

namespace tablet {
class Tablet;
class TabletPeer;
class TransactionState;
} // namespace tablet

namespace tserver {

class ScanResultCollector;
class TabletPeerLookupIf;
class TabletServer;

class TabletServiceImpl : public TabletServerServiceIf {
 public:
  explicit TabletServiceImpl(TabletServer* server);

  virtual void Ping(const PingRequestPB* req,
                    PingResponsePB* resp,
                    rpc::RpcContext* context) OVERRIDE;

  virtual void Write(const WriteRequestPB* req, WriteResponsePB* resp,
                   rpc::RpcContext* context) OVERRIDE;

  virtual void Scan(const ScanRequestPB* req,
                    ScanResponsePB* resp,
                    rpc::RpcContext* context) OVERRIDE;

  virtual void ListTablets(const ListTabletsRequestPB* req,
                           ListTabletsResponsePB* resp,
                           rpc::RpcContext* context) OVERRIDE;

  virtual void Checksum(const ChecksumRequestPB* req,
                        ChecksumResponsePB* resp,
                        rpc::RpcContext* context) OVERRIDE;

  virtual void Shutdown() OVERRIDE;

 private:
  Status HandleNewScanRequest(tablet::TabletPeer* tablet_peer,
                              const ScanRequestPB* req,
                              const rpc::RpcContext* rpc_context,
                              ScanResultCollector* result_collector,
                              std::string* scanner_id,
                              Timestamp* snap_timestamp,
                              bool* has_more_results,
                              TabletServerErrorPB::Code* error_code);

  Status HandleContinueScanRequest(const ScanRequestPB* req,
                                   ScanResultCollector* result_collector,
                                   bool* has_more_results,
                                   TabletServerErrorPB::Code* error_code);

  Status HandleScanAtSnapshot(const NewScanRequestPB& scan_pb,
                              const rpc::RpcContext* rpc_context,
                              const Schema& projection,
                              const std::tr1::shared_ptr<tablet::Tablet>& tablet,
                              gscoped_ptr<RowwiseIterator>* iter,
                              Timestamp* snap_timestamp);

  TabletServer* server_;
};

class TabletServiceAdminImpl : public TabletServerAdminServiceIf {
 public:
  explicit TabletServiceAdminImpl(TabletServer* server);
  virtual void CreateTablet(const CreateTabletRequestPB* req,
                            CreateTabletResponsePB* resp,
                            rpc::RpcContext* context) OVERRIDE;

  virtual void DeleteTablet(const DeleteTabletRequestPB* req,
                            DeleteTabletResponsePB* resp,
                            rpc::RpcContext* context) OVERRIDE;

  virtual void AlterSchema(const AlterSchemaRequestPB* req,
                           AlterSchemaResponsePB* resp,
                           rpc::RpcContext* context) OVERRIDE;

 private:
  TabletServer* server_;
};

class ConsensusServiceImpl : public consensus::ConsensusServiceIf {
 public:
  ConsensusServiceImpl(const scoped_refptr<MetricEntity>& metric_entity,
                       TabletPeerLookupIf* tablet_manager_);

  virtual ~ConsensusServiceImpl();

  virtual void UpdateConsensus(const consensus::ConsensusRequestPB *req,
                               consensus::ConsensusResponsePB *resp,
                               rpc::RpcContext *context) OVERRIDE;

  virtual void RequestConsensusVote(const consensus::VoteRequestPB* req,
                                    consensus::VoteResponsePB* resp,
                                    rpc::RpcContext* context) OVERRIDE;

  virtual void ChangeConfig(const consensus::ChangeConfigRequestPB* req,
                         consensus::ChangeConfigResponsePB* resp,
                         rpc::RpcContext* context) OVERRIDE;

  virtual void GetNodeInstance(const consensus::GetNodeInstanceRequestPB* req,
                               consensus::GetNodeInstanceResponsePB* resp,
                               rpc::RpcContext* context) OVERRIDE;

  virtual void RunLeaderElection(const consensus::RunLeaderElectionRequestPB* req,
                                 consensus::RunLeaderElectionResponsePB* resp,
                                 rpc::RpcContext* context) OVERRIDE;

  virtual void LeaderStepDown(const consensus::LeaderStepDownRequestPB* req,
                                 consensus::LeaderStepDownResponsePB* resp,
                                 rpc::RpcContext* context) OVERRIDE;

  virtual void GetLastOpId(const consensus::GetLastOpIdRequestPB *req,
                           consensus::GetLastOpIdResponsePB *resp,
                           rpc::RpcContext *context) OVERRIDE;

  virtual void GetConsensusState(const consensus::GetConsensusStateRequestPB *req,
                                 consensus::GetConsensusStateResponsePB *resp,
                                 rpc::RpcContext *context) OVERRIDE;

  virtual void StartRemoteBootstrap(const consensus::StartRemoteBootstrapRequestPB* req,
                                    consensus::StartRemoteBootstrapResponsePB* resp,
                                    rpc::RpcContext* context) OVERRIDE;

 private:
  TabletPeerLookupIf* tablet_manager_;
};

} // namespace tserver
} // namespace kudu

#endif
