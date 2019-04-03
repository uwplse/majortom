// Copyright (c) 2014, Cloudera, inc.
// Confidential Cloudera Information: Covered by NDA.

#include <boost/lexical_cast.hpp>
#include <boost/assign/list_of.hpp>
#include <boost/foreach.hpp>
#include <gtest/gtest.h>

#include "kudu/gutil/strings/substitute.h"
#include "kudu/gutil/map-util.h"
#include "kudu/tools/ksck.h"
#include "kudu/util/test_util.h"

namespace kudu {
namespace tools {

using std::tr1::shared_ptr;
using std::tr1::static_pointer_cast;
using std::tr1::unordered_map;
using std::string;
using std::vector;

class MockKsckTabletServer : public KsckTabletServer {
 public:
  explicit MockKsckTabletServer(const string& uuid)
      : KsckTabletServer(uuid),
        connect_status_(Status::OK()),
        address_("<mock>") {
  }

  virtual Status Connect() const OVERRIDE {
    return connect_status_;
  }

  virtual void RunTabletChecksumScanAsync(
      const std::string& tablet_id,
      const Schema& schema,
      const ChecksumOptions& options,
      const ReportResultCallback& callback) OVERRIDE {
    callback.Run(Status::OK(), 0);
  }

  virtual Status CurrentTimestamp(uint64_t* timestamp) const OVERRIDE {
    *timestamp = 0;
    return Status::OK();
  }

  virtual const std::string& address() const OVERRIDE {
    return address_;
  }

  // Public because the unit tests mutate this variable directly.
  Status connect_status_;

 private:
  const string address_;
};

class MockKsckMaster : public KsckMaster {
 public:
  MockKsckMaster()
      : connect_status_(Status::OK()) {
  }

  virtual Status Connect() const OVERRIDE {
    return connect_status_;
  }

  virtual Status RetrieveTabletServers(TSMap* tablet_servers) OVERRIDE {
    *tablet_servers = tablet_servers_;
    return Status::OK();
  }

  virtual Status RetrieveTablesList(vector<shared_ptr<KsckTable> >* tables) OVERRIDE {
    tables->assign(tables_.begin(), tables_.end());
    return Status::OK();
  }

  virtual Status RetrieveTabletsList(const shared_ptr<KsckTable>& table) OVERRIDE {
    return Status::OK();
  }

  // Public because the unit tests mutate these variables directly.
  Status connect_status_;
  TSMap tablet_servers_;
  vector<shared_ptr<KsckTable> > tables_;
};

class KsckTest : public KuduTest {
 public:
  KsckTest()
      : master_(new MockKsckMaster()),
        cluster_(new KsckCluster(static_pointer_cast<KsckMaster>(master_))),
        ksck_(new Ksck(cluster_)) {
    unordered_map<string, shared_ptr<KsckTabletServer> > tablet_servers;
    for (int i = 0; i < 3; i++) {
      string name = strings::Substitute("$0", i);
      shared_ptr<MockKsckTabletServer> ts(new MockKsckTabletServer(name));
      InsertOrDie(&tablet_servers, ts->uuid(), ts);
    }
    master_->tablet_servers_.swap(tablet_servers);
  }

 protected:
  void CreateDefaultAssignmentPlan(int tablets_count) {
    while (tablets_count > 0) {
      BOOST_FOREACH(const KsckMaster::TSMap::value_type& entry, master_->tablet_servers_) {
        if (tablets_count-- == 0) return;
        assignment_plan_.push_back(entry.second->uuid());
      }
    }
  }

  void CreateOneTableOneTablet() {
    CreateDefaultAssignmentPlan(1);

    shared_ptr<KsckTablet> tablet(new KsckTablet("1"));
    CreateAndFillTablet(tablet, 1, true);

    CreateAndAddTable(boost::assign::list_of(tablet), "test", 1);
  }

  void CreateOneSmallReplicatedTable() {
    int num_replicas = 3;
    int num_tablets = 3;
    vector<shared_ptr<KsckTablet> > tablets;
    CreateDefaultAssignmentPlan(num_replicas * num_tablets);
    for (int i = 0; i < num_tablets; i++) {
      shared_ptr<KsckTablet> tablet(new KsckTablet(boost::lexical_cast<string>(i)));
      CreateAndFillTablet(tablet, num_replicas, true);
      tablets.push_back(tablet);
    }

    CreateAndAddTable(tablets, "test", num_replicas);
  }

  void CreateOneOneTabletReplicatedBrokenTable() {
    // We're placing only two tablets, the 3rd goes nowhere.
    CreateDefaultAssignmentPlan(2);

    shared_ptr<KsckTablet> tablet(new KsckTablet("1"));
    CreateAndFillTablet(tablet, 2, false);

    CreateAndAddTable(boost::assign::list_of(tablet), "test", 3);
  }

  void CreateAndAddTable(vector<shared_ptr<KsckTablet> > tablets,
                         const string& name, int num_replicas) {
    shared_ptr<KsckTable> table(new KsckTable(name, Schema(), num_replicas));
    table->set_tablets(tablets);

    vector<shared_ptr<KsckTable> > tables = boost::assign::list_of(table);
    master_->tables_.assign(tables.begin(), tables.end());
  }

  void CreateAndFillTablet(shared_ptr<KsckTablet>& tablet, int num_replicas, bool has_leader) {
    vector<shared_ptr<KsckTabletReplica> > replicas;
    if (has_leader) {
      CreateReplicaAndAdd(replicas, true);
      num_replicas--;
    }
    for (int i = 0; i < num_replicas; i++) {
      CreateReplicaAndAdd(replicas, false);
    }
    tablet->set_replicas(replicas);
  }

  void CreateReplicaAndAdd(vector<shared_ptr<KsckTabletReplica> >& replicas, bool is_leader) {
    shared_ptr<KsckTabletReplica> replica(new KsckTabletReplica(assignment_plan_.back(),
                                                                is_leader, !is_leader));
    assignment_plan_.pop_back();
    replicas.push_back(replica);
  }

  shared_ptr<MockKsckMaster> master_;
  shared_ptr<KsckCluster> cluster_;
  shared_ptr<Ksck> ksck_;
  // This is used as a stack. First the unit test is responsible to create a plan to follow, that
  // is the order in which each replica of each tablet will be assigned, starting from the end.
  // So if you have 2 tablets with num_replicas=3 and 3 tablet servers, then to distribute evenly
  // you should have a list that looks like ts1,ts2,ts3,ts3,ts2,ts1 so that the two LEADERS, which
  // are assigned first, end up on ts1 and ts3.
  vector<string> assignment_plan_;
};

TEST_F(KsckTest, TestMasterOk) {
  ASSERT_OK(ksck_->CheckMasterRunning());
}

TEST_F(KsckTest, TestMasterUnavailable) {
  Status error = Status::NetworkError("Network failure");
  master_->connect_status_ = error;
  ASSERT_TRUE(ksck_->CheckMasterRunning().IsNetworkError());
}

TEST_F(KsckTest, TestTabletServersOk) {
  ASSERT_OK(ksck_->CheckMasterRunning());
  ASSERT_OK(ksck_->FetchTableAndTabletInfo());
  ASSERT_OK(ksck_->CheckTabletServersRunning());
}

TEST_F(KsckTest, TestBadTabletServer) {
  ASSERT_OK(ksck_->CheckMasterRunning());
  Status error = Status::NetworkError("Network failure");
  static_pointer_cast<MockKsckTabletServer>(master_->tablet_servers_.begin()->second)
      ->connect_status_ = error;
  ASSERT_OK(ksck_->FetchTableAndTabletInfo());
  Status s = ksck_->CheckTabletServersRunning();
  ASSERT_TRUE(s.IsNetworkError()) << "Status returned: " << s.ToString();
}

TEST_F(KsckTest, TestZeroTableCheck) {
  ASSERT_OK(ksck_->CheckMasterRunning());
  ASSERT_OK(ksck_->FetchTableAndTabletInfo());
  ASSERT_OK(ksck_->CheckTabletServersRunning());
  ASSERT_OK(ksck_->CheckTablesConsistency());
}

TEST_F(KsckTest, TestOneTableCheck) {
  CreateOneTableOneTablet();
  ASSERT_OK(ksck_->CheckMasterRunning());
  ASSERT_OK(ksck_->FetchTableAndTabletInfo());
  ASSERT_OK(ksck_->CheckTabletServersRunning());
  ASSERT_OK(ksck_->CheckTablesConsistency());
}

TEST_F(KsckTest, TestOneSmallReplicatedTable) {
  CreateOneSmallReplicatedTable();
  ASSERT_OK(ksck_->CheckMasterRunning());
  ASSERT_OK(ksck_->FetchTableAndTabletInfo());
  ASSERT_OK(ksck_->CheckTabletServersRunning());
  ASSERT_OK(ksck_->CheckTablesConsistency());
}

TEST_F(KsckTest, TestOneOneTabletBrokenTable) {
  CreateOneOneTabletReplicatedBrokenTable();
  ASSERT_OK(ksck_->CheckMasterRunning());
  ASSERT_OK(ksck_->FetchTableAndTabletInfo());
  ASSERT_OK(ksck_->CheckTabletServersRunning());
  ASSERT_TRUE(ksck_->CheckTablesConsistency().IsCorruption());
}

} // namespace tools
} // namespace kudu
