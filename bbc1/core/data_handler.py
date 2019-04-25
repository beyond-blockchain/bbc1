# -*- coding: utf-8 -*-
"""
Copyright (c) 2017 beyond-blockchain.org.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

import traceback
import binascii
import os
import sys
sys.path.extend(["../../", os.path.abspath(os.path.dirname(__file__))])
from bbc1.core import bbclib
import bbc1.core.libs.bbclib_config as bbclib_config
from bbc1.core.message_key_types import to_2byte, PayloadType, KeyType, InfraMessageCategory
from bbc1.core import logger


DB_VERSION = "ver=2"


version_tbl_definition = [
    ["version", "TEXT"]
]

transaction_tbl_definition = [
    ["transaction_id", "BLOB"], ["transaction_data", "BLOB"],
]

asset_info_definition = [
    ["id", "INTEGER"],
    ["transaction_id", "BLOB"], ["asset_group_id", "BLOB"], ["asset_id", "BLOB"], ["user_id", "BLOB"], ["timestamp", "BIGINT"],
]

topology_info_definition = [
    ["id", "INTEGER"], ["base", "BLOB"], ["point_to", "BLOB"]
]

cross_ref_tbl_definition = [
    ["id", "INTEGER"], ["transaction_id", "BLOB"], ["outer_domain_id", "BLOB"], ["txid_having_cross_ref", "BLOB"],
]

#--- for anchoring ethereum/bitcoin blockchain ---
merkle_branch_db_definition = [
    ["digest", "BLOB"], ["leaf_left", "BLOB"], ["leaf_right", "BLOB"],
]

merkle_leaf_db_definition = [
    ["digest", "BLOB"], ["leaf_left", "BLOB"], ["leaf_right", "BLOB"], ["prev", "BLOB"],
]

merkle_root_db_definition = [
    ["root", "BLOB"], ["spec", "BLOB"],
]


class DataHandler:
    """DB and storage handler"""
    REPLICATION_ALL = 0
    REPLICATION_P2P = 1
    REPLICATION_EXT = 2
    REQUEST_REPLICATION_INSERT = to_2byte(0)
    RESPONSE_REPLICATION_INSERT = to_2byte(1)
    REQUEST_SEARCH = to_2byte(2)
    RESPONSE_SEARCH = to_2byte(3)
    NOTIFY_INSERTED = to_2byte(4)
    REPAIR_TRANSACTION_DATA = to_2byte(5)
    REPLICATION_CROSS_REF = to_2byte(6)

    def __init__(self, networking=None, config=None, workingdir=None, domain_id=None, loglevel="all", logname=None):
        self.networking = networking
        self.core = networking.core
        self.stats = networking.core.stats
        self.logger = logger.get_logger(key="data_handler", level=loglevel, logname=logname)
        self.domain_id = domain_id
        self.domain_id_str = bbclib.convert_id_to_string(domain_id)
        self.config = config
        self.working_dir = workingdir
        self.storage_root = os.path.join(self.working_dir, self.domain_id_str)
        if not os.path.exists(self.storage_root):
            os.makedirs(self.storage_root, exist_ok=True)
        self.use_external_storage = self._storage_setup()
        self.replication_strategy = DataHandler.REPLICATION_ALL
        self.upgraded_from = DB_VERSION
        self.db_adaptors = list()
        self._db_setup()

    def _db_setup(self):
        """Setup DB"""
        dbconf = self.config['db']
        if dbconf['replication_strategy'] == 'all':
            self.replication_strategy = DataHandler.REPLICATION_ALL
        elif dbconf['replication_strategy'] == 'p2p':
            self.replication_strategy = DataHandler.REPLICATION_P2P
        else:
            self.replication_strategy = DataHandler.REPLICATION_EXT
        db_type = dbconf.get("db_type", "sqlite")
        db_name = dbconf.get("db_name", "bbc1_db.sqlite")
        if db_type == "sqlite":
            self.db_adaptors.append(SqliteAdaptor(self, db_name=os.path.join(self.storage_root, db_name)))
        elif db_type == "mysql":
            count = 0
            for c in dbconf['db_servers']:
                db_addr = c.get("db_addr", "127.0.0.1")
                db_port = c.get("db_port", 3306)
                db_user = c.get("db_user", "user")
                db_pass = c.get("db_pass", "password")
                self.db_adaptors.append(MysqlAdaptor(self, db_name=db_name, db_num=count,
                                                     server_info=(db_addr, db_port, db_user, db_pass)))
                count += 1

        for db in self.db_adaptors:
            db.open_db()
            flag_created = db.create_table('transaction_table', transaction_tbl_definition, primary_key=0, indices=[0])
            db.create_table('asset_info_table', asset_info_definition, primary_key=0, indices=[0, 1, 2, 3, 4, 5])
            db.create_table('topology_table', topology_info_definition, primary_key=0, indices=[0, 1, 2])
            db.create_table('cross_ref_table', cross_ref_tbl_definition, primary_key=0, indices=[1])
            db.create_table('merkle_branch_table', merkle_branch_db_definition, primary_key=0, indices=[1, 2])
            db.create_table('merkle_leaf_table', merkle_leaf_db_definition, primary_key=0, indices=[1, 2])
            db.create_table('merkle_root_table', merkle_root_db_definition, primary_key=0, indices=[0])
            ver = db.get_version()
            if ver != DB_VERSION:
                if not flag_created:
                    self.logger.fatal("*** DB meta table is upgraded. Run db_migration_tool.py")
                    self.upgraded_from = ver
                db.update_table_def(ver)

    def _storage_setup(self):
        """Setup storage"""
        if self.config['storage']['type'] == "external":
            return True
        if 'root' in self.config['storage'] and self.config['storage']['root'].startswith("/"):
            self.storage_root = os.path.join(self.config['storage']['root'], self.domain_id_str)
        else:
            self.storage_root = os.path.join(self.working_dir, self.domain_id_str)
        os.makedirs(self.storage_root, exist_ok=True)
        return False

    def exec_sql(self, db_num=0, sql=None, args=(), commit=False, fetch_one=False, return_cursor=False):
        """Execute sql sentence

        Args:
            db_num (int): index of DB if multiple DBs are used
            sql (str): SQL string
            args (list): Args for the SQL
            commit (bool): If True, commit is performed
            fetch_one (bool): If True, fetch just one record
            return_cursor (bool): If True (and fetch_one is False), return db_cur (iterator)
        Returns:
            list: list of records
        """
        self.stats.update_stats_increment("data_handler", "exec_sql", 1)
        #print("sql=", sql)
        #if len(args) > 0:
        #    print("args=", args)
        try:
            db_num = 0 if db_num >= len(self.db_adaptors) else db_num
            if len(args) > 0:
                self.db_adaptors[db_num].db_cur.execute(sql, args)
            else:
                self.db_adaptors[db_num].db_cur.execute(sql)
            self.db_adaptors[db_num].db.commit()  # commit is mandatory (even if read access) in that case that multiple client connect to a single mysql server
            if commit:
                ret = None
            else:
                if fetch_one:
                    ret = self.db_adaptors[db_num].db_cur.fetchone()
                    self.db_adaptors[db_num].db.commit()
                else:
                    if return_cursor:
                        return self.db_adaptors[db_num].db_cur
                    ret = self.db_adaptors[db_num].db_cur.fetchall()
        except:
            if commit:
                self.db_adaptors[db_num].db.rollback()
            self.logger.error(traceback.format_exc())
            traceback.print_exc()
            self.stats.update_stats_increment("data_handler", "fail_exec_sql", 1)
            if self.db_adaptors[db_num] is not None and self.db_adaptors[db_num].db_cur is not None:
                self.db_adaptors[db_num].db_cur.close()
            if self.db_adaptors[db_num] is not None and self.db_adaptors[db_num].db is not None:
                self.db_adaptors[db_num].db.close()
            self.db_adaptors[db_num].open_db()
            return None

        if ret is None:
            return []
        else:
            return list(ret)

    def get_asset_info(self, txobj):
        """Retrieve asset information from transaction object

        Args:
            txobj (BBcTransaction): transaction object to analyze
        Returns:
            list: list of list [asset_group_id, asset_id, user_id, file_size, file_digest]
        """
        info = list()
        for idx, evt in enumerate(txobj.events):
            ast = evt.asset
            if ast is not None:
                info.append((evt.asset_group_id, ast.asset_id, ast.user_id, ast.asset_file_size>0,
                             ast.asset_file_digest))
        for idx, rtn in enumerate(txobj.relations):
            ast = rtn.asset
            if rtn.asset is not None:
                info.append((rtn.asset_group_id, ast.asset_id, ast.user_id, ast.asset_file_size>0,
                             ast.asset_file_digest))
        return info

    def _get_topology_info(self, txobj):
        """Retrieve topology information from transaction object

        This method returns (from, to) list that describe the topology of transactions

        Args:
            txobj (BBcTransaction): transaction object to analyze
        Returns:
            list: list of tuple (base transaction_id, pointing transaction_id)
        """
        info = list()
        for reference in txobj.references:
            info.append((txobj.transaction_id, reference.transaction_id))  # (base, point_to)
        for idx, rtn in enumerate(txobj.relations):
            for pt in rtn.pointers:
                info.append((txobj.transaction_id, pt.transaction_id))  # (base, point_to)
        return info

    def insert_transaction(self, txdata, txobj=None, fmt_type=bbclib_config.DEFAULT_BBC_FORMAT, asset_files=None, no_replication=False):
        """Insert transaction data and its asset files

        Either txdata or txobj must be given to insert the transaction.

        Args:
            txdata (bytes): serialized transaction data
            txobj (BBcTransaction): transaction object to insert
            fmt_type (int): 2-byte value of BBcFormat type
            asset_files (dict): asset files in the transaction
        Returns:
            set: set of asset_group_ids in the transaction
        """
        self.stats.update_stats_increment("data_handler", "insert_transaction", 1)
        if txobj is None:
            txobj, fmt_type = self.core.validate_transaction(txdata, asset_files=asset_files)
            if txobj is None:
                return None

        inserted_count = 0
        for i in range(len(self.db_adaptors)):
            if self._insert_transaction_into_a_db(i, txobj, fmt_type):
                inserted_count += 1
        if inserted_count == 0:
            return None

        asset_group_ids = self._store_asset_files(txobj, asset_files)

        if not no_replication and self.replication_strategy != DataHandler.REPLICATION_EXT:
            self._send_replication_to_other_cores(txdata, asset_files)

        if self.networking.domain0manager is not None:
            self.networking.domain0manager.distribute_cross_ref_in_domain0(domain_id=self.domain_id,
                                                                           transaction_id=txobj.transaction_id)
            if txobj.cross_ref is not None:
                self.networking.domain0manager.cross_ref_registered(domain_id=self.domain_id,
                                                                    transaction_id=txobj.transaction_id,
                                                                    cross_ref=(txobj.cross_ref.domain_id,
                                                                               txobj.cross_ref.transaction_id))

        return asset_group_ids

    def _insert_transaction_into_a_db(self, db_num, txobj, fmt_type=bbclib_config.DEFAULT_BBC_FORMAT):
        """Insert transaction data into the transaction table of the specified DB

        Args:
            db_num (int): index of DB if multiple DBs are used
            txobj (BBcTransaction): transaction object to insert
            fmt_type (int): 2-byte value of BBcFormat type
        Returns:
            bool: True if successful
        """
        #print("_insert_transaction_into_a_db: for txid =", txobj.transaction_id.hex())
        txdata = bbclib.serialize(txobj, format_type=fmt_type)
        ret = self.exec_sql(db_num=db_num,
                            sql="INSERT INTO transaction_table VALUES (%s,%s)" % (self.db_adaptors[0].placeholder,
                                                                                  self.db_adaptors[0].placeholder),
                            args=(txobj.transaction_id, txdata), commit=True)
        if ret is None:
            return False

        ts = txobj.timestamp
        for asset_group_id, asset_id, user_id, fileflag, filedigest in self.get_asset_info(txobj):
            self.exec_sql(db_num=db_num,
                          sql="INSERT INTO asset_info_table(transaction_id, asset_group_id, asset_id, user_id, timestamp) "
                              "VALUES (%s, %s, %s, %s, %s)" % (
                              self.db_adaptors[0].placeholder, self.db_adaptors[0].placeholder,
                              self.db_adaptors[0].placeholder, self.db_adaptors[0].placeholder,
                              self.db_adaptors[0].placeholder),
                          args=(txobj.transaction_id, asset_group_id, asset_id, user_id, ts), commit=True)
        for base, point_to in self._get_topology_info(txobj):
            self.exec_sql(db_num=db_num,
                          sql="INSERT INTO topology_table(base, point_to) VALUES (%s, %s)" %
                              (self.db_adaptors[0].placeholder, self.db_adaptors[0].placeholder),
                          args=(base, point_to), commit=True)
            #print("topology: base:%s, point_to:%s" % (base.hex(), point_to.hex()))
        return True

    def insert_cross_ref(self, transaction_id, outer_domain_id, txid_having_cross_ref, no_replication=False):
        """Insert cross_ref information into cross_ref_table

        Args:
            transaction_id (bytes): target transaction_id
            outer_domain_id (bytes): domain_id that holds cross_ref about the transaction_id
            txid_having_cross_ref (bytes): transaction_id in the outer_domain that includes the cross_ref
            no_replication (bool): If False, the replication is sent to other nodes in the domain
        """
        self.stats.update_stats_increment("data_handler", "insert_cross_ref", 1)
        sql = "INSERT INTO cross_ref_table (transaction_id, outer_domain_id, txid_having_cross_ref) " + \
              "VALUES (%s, %s, %s)" % (self.db_adaptors[0].placeholder, self.db_adaptors[0].placeholder,
                                       self.db_adaptors[0].placeholder)
        for i in range(len(self.db_adaptors)):
            self.exec_sql(db_num=i, sql=sql, args=(transaction_id, outer_domain_id, txid_having_cross_ref), commit=True)

        if not no_replication:
            self._send_cross_ref_replication_to_other_cores(transaction_id, outer_domain_id, txid_having_cross_ref)

    def count_domain_in_cross_ref(self, outer_domain_id):
        """Count the number of domains in the cross_ref table"""
        # TODO: need to consider registered_time
        sql = "SELECT count(*) FROM cross_ref_table WHERE outer_domain = %s" % self.db_adaptors[0].placeholder
        ret = self.exec_sql(sql=sql, args=(outer_domain_id,))
        return ret

    def search_domain_having_cross_ref(self, transaction_id=None):
        """Search domain_id that holds cross_ref about the specified transaction_id

        Args:
            transaction_id (bytes): target transaction_id
        Returns:
            list: records of cross_ref_tables ["id","transaction_id", "outer_domain_id", "txid_having_cross_ref"]
        """
        if transaction_id is not None:
            sql = "SELECT * FROM cross_ref_table WHERE transaction_id = %s" % self.db_adaptors[0].placeholder
            return self.exec_sql(sql=sql, args=(transaction_id,))
        else:
            return self.exec_sql(sql="SELECT * FROM cross_ref_table")

    def _store_asset_files(self, txobj, asset_files):
        """Store all asset_files related to the transaction_object

        Args:
            txobj (BBcTransaction): transaction object to insert
            asset_files (dict): dictionary of {asset_id: content} for the transaction
        Returns:
            set: set of asset_group_ids in the transaction
        """
        #print("_store_asset_files: for txid =", txobj.transaction_id.hex())
        asset_group_ids = set()
        for asset_group_id, asset_id, user_id, fileflag, filedigest in self.get_asset_info(txobj):
            asset_group_ids.add(asset_group_id)
            if not self.use_external_storage and asset_files is not None and asset_id in asset_files:
                self.store_in_storage(asset_group_id, asset_id, asset_files[asset_id])
        return asset_group_ids

    def restore_transaction_data(self, db_num, transaction_id, txobj):
        """Remove and insert a transaction"""
        if txobj is not None:
            self.remove(transaction_id, txobj=txobj, db_num=db_num)
            self._insert_transaction_into_a_db(db_num=db_num, txobj=txobj)

    def _send_replication_to_other_cores(self, txdata, asset_files=None):
        """Broadcast replication of transaction data"""
        msg = {
            KeyType.domain_id: self.domain_id,
            KeyType.infra_msg_type: InfraMessageCategory.CATEGORY_DATA,
            KeyType.infra_command: DataHandler.REQUEST_REPLICATION_INSERT,
            KeyType.transaction_data: txdata,
        }
        if asset_files is not None:
            msg[KeyType.all_asset_files] = asset_files
        if self.replication_strategy == DataHandler.REPLICATION_ALL:
            self.networking.broadcast_message_in_network(domain_id=self.domain_id,
                                                         payload_type=PayloadType.Type_any, msg=msg)
        elif self.replication_strategy == DataHandler.REPLICATION_P2P:
            pass  # TODO: implement (destinations determined by TopologyManager)

    def _send_cross_ref_replication_to_other_cores(self, transaction_id, outer_domain_id, txid_having_cross_ref):
        """Broadcast replication of cross_ref

        Args:
            transaction_id (bytes): target transaction_id
            outer_domain_id (bytes): domain_id that holds cross_ref about the transaction_id
            txid_having_cross_ref (bytes): transaction_id in the outer_domain that includes the cross_ref
        """
        msg = {
            KeyType.domain_id: self.domain_id,
            KeyType.infra_msg_type: InfraMessageCategory.CATEGORY_DATA,
            KeyType.infra_command: DataHandler.REPLICATION_CROSS_REF,
            KeyType.transaction_id: transaction_id,
            KeyType.outer_domain_id: outer_domain_id,
            KeyType.txid_having_cross_ref: txid_having_cross_ref,
        }
        if self.replication_strategy == DataHandler.REPLICATION_ALL:
            self.networking.broadcast_message_in_network(domain_id=self.domain_id,
                                                         payload_type=PayloadType.Type_any, msg=msg)
        elif self.replication_strategy == DataHandler.REPLICATION_P2P:
            pass  # TODO: implement (destinations determined by TopologyManager)

    def remove(self, transaction_id, txobj=None, db_num=-1):
        """Delete all data regarding the specified transaction_id

        This method requires either transaction_id or txobj.

        Args:
            transaction_id (bytes): target transaction_id
            txobj (BBcTransaction): transaction object to remove
            db_num (int): index of DB if multiple DBs are used
        """
        if transaction_id is None:
            return
        if txobj is None:
            txdata = self.exec_sql(sql="SELECT * FROM transaction_table WHERE transaction_id = %s" %
                                   self.db_adaptors[0].placeholder, args=(transaction_id,))
            txobj, fmt_type = bbclib.deserialize(txdata[0][1])
        elif txobj.transaction_id != transaction_id:
            return

        if db_num == -1 or db_num >= len(self.db_adaptors):
            for i in range(len(self.db_adaptors)):
                self._remove_transaction(txobj, i)
        else:
            self._remove_transaction(txobj, db_num)

    def _remove_transaction(self, txobj, db_num):
        """Remove transaction from DB"""
        #print("_remove_transaction: for txid =", txobj.transaction_id.hex())
        self.exec_sql(
            db_num=db_num,
            sql="DELETE FROM transaction_table WHERE transaction_id = %s" % self.db_adaptors[0].placeholder,
            args=(txobj.transaction_id,), commit=True)
        for base, point_to in self._get_topology_info(txobj):
            self.exec_sql(
                db_num=db_num,
                sql="DELETE FROM topology_table WHERE base = %s AND point_to = %s" %
                    (self.db_adaptors[0].placeholder,self.db_adaptors[0].placeholder),
                args=(base, point_to), commit=True)

    def _remove_asset_files(self, txobj, asset_files=None):
        """Remove all asset files related to the transaction

        If asset_files is given, only asset files in given param are removed

        Args:
            txobj (BBcTransaction): transaction object that includes the asset to be removed
            asset_files (dict): dictionary of {asset_id: content} for the transaction
        """
        #print("_remove_asset_files: for txid =", txobj.transaction_id.hex())
        if self.use_external_storage:
            return
        for asset_group_id, asset_id, user_id, fileflag, filedigest in self.get_asset_info(txobj):
            if asset_files is not None:
                if asset_id in asset_files:
                    self._remove_in_storage(asset_group_id, asset_id)
            else:
                self._remove_in_storage(asset_group_id, asset_id)

    def search_transaction(self, transaction_id=None, asset_group_id=None, asset_id=None, user_id=None,
                           start_from=None, until=None, direction=0, count=1, db_num=0):
        """Search transaction data

        When Multiple conditions are given, they are considered as AND condition.

        Args:
            transaction_id (bytes): target transaction_id
            asset_group_id (bytes): asset_group_id that target transactions should have
            asset_id (bytes): asset_id that target transactions should have
            user_id (bytes): user_id that target transactions should have
            start_from (int): the starting timestamp to search
            until (int): the end timestamp to search
            direction (int): 0: descend, 1: ascend
            count (int): The maximum number of transactions to retrieve
            db_num (int): index of DB if multiple DBs are used
        Returns:
            dict: mapping from transaction_id to serialized transaction data
            dict: dictionary of {asset_id: content} for the transaction
        """
        if transaction_id is not None:
            txinfo = self.exec_sql(
                db_num=db_num,
                sql="SELECT * FROM transaction_table WHERE transaction_id = %s" % self.db_adaptors[0].placeholder,
                args=(transaction_id,))
            if len(txinfo) == 0:
                return None, None
        else:
            dire = "DESC"
            if direction == 1:
                dire = "ASC"
            sql = "SELECT * from asset_info_table WHERE "
            conditions = list()
            if asset_group_id is not None:
                conditions.append("asset_group_id = %s " % self.db_adaptors[0].placeholder)
            if asset_id is not None:
                conditions.append("asset_id = %s " % self.db_adaptors[0].placeholder)
            if user_id is not None:
                conditions.append("user_id = %s " % self.db_adaptors[0].placeholder)
            if start_from is not None:
                conditions.append("timestamp >= %s " % self.db_adaptors[0].placeholder)
            if until is not None:
                conditions.append("timestamp <= %s " % self.db_adaptors[0].placeholder)
            sql += "AND ".join(conditions) + "ORDER BY id %s" % dire
            if count > 0:
                sql += " limit %d" % count
            sql += ";"
            args = list(filter(lambda a: a is not None, (asset_group_id, asset_id, user_id, start_from, until)))
            ret = self.exec_sql(db_num=db_num, sql=sql, args=args)
            txinfo = list()
            for record in ret:
                tx = self.exec_sql(
                    db_num=db_num,
                    sql="SELECT * FROM transaction_table WHERE transaction_id = %s" % self.db_adaptors[0].placeholder,
                    args=(record[1],))
                if tx is not None and len(tx) == 1:
                    txinfo.append(tx[0])

        result_txobj = dict()
        result_asset_files = dict()
        for txid, txdata in txinfo:
            txobj, fmt_type = bbclib.deserialize(txdata)
            result_txobj[txid] = txobj
            for asset_group_id, asset_id, user_id, fileflag, filedigest in self.get_asset_info(txobj):
                if fileflag:
                    result_asset_files[asset_id] = self.get_in_storage(asset_group_id, asset_id)
        return result_txobj, result_asset_files

    def count_transactions(self, asset_group_id=None, asset_id=None, user_id=None, start_from=None, until=None, db_num=0):
        """Count transactions that matches the given conditions

        When Multiple conditions are given, they are considered as AND condition.

        Args:
            asset_group_id (bytes): asset_group_id that target transactions should have
            asset_id (bytes): asset_id that target transactions should have
            user_id (bytes): user_id that target transactions should have
            start_from (int): the starting timestamp to search
            until (int): the end timestamp to search
            db_num (int): index of DB if multiple DBs are used
        Returns:
            int: the number of transactions
        """
        sql = "SELECT count( DISTINCT transaction_id ) from asset_info_table WHERE "
        conditions = list()
        if asset_group_id is not None:
            conditions.append("asset_group_id = %s " % self.db_adaptors[0].placeholder)
        if asset_id is not None:
            conditions.append("asset_id = %s " % self.db_adaptors[0].placeholder)
        if user_id is not None:
            conditions.append("user_id = %s " % self.db_adaptors[0].placeholder)
        if start_from is not None:
            conditions.append("timestamp >= %s " % self.db_adaptors[0].placeholder)
        if until is not None:
            conditions.append("timestamp <= %s " % self.db_adaptors[0].placeholder)
        sql += "AND ".join(conditions)
        args = list(filter(lambda a: a is not None, (asset_group_id, asset_id, user_id, start_from, until)))
        ret = self.exec_sql(db_num=db_num, sql=sql, args=args)
        return ret[0][0]

    def search_transaction_topology(self, transaction_id, traverse_to_past=True):
        """Search in topology info

        Args:
            transaction_id (bytes): base transaction_id
            traverse_to_past (bool): True: search backward (to past), False: search forward (to future)
        Returns:
            list: list of records of topology table
        """
        if transaction_id is None:
            return None
        if traverse_to_past:
            return self.exec_sql(sql="SELECT * FROM topology_table WHERE base = %s" %
                                 self.db_adaptors[0].placeholder, args=(transaction_id,))

        else:
            return self.exec_sql(sql="SELECT * FROM topology_table WHERE point_to = %s" %
                                 self.db_adaptors[0].placeholder, args=(transaction_id,))

    def store_in_storage(self, asset_group_id, asset_id, content, do_overwrite=False):
        """Store asset file in local storage

        Args:
            asset_group_id (bytes): asset_group_id of the asset
            asset_id (bytes): asset_id of the asset
            content (bytes): the content of the asset file
            do_overwrite (bool): If True, file is overwritten
        Returns:
            bool: True if successful
        """
        #print("store_in_storage: for asset_id =", asset_id.hex())
        self.stats.update_stats_increment("data_handler", "store_in_storage", 1)
        asset_group_id_str = binascii.b2a_hex(asset_group_id).decode('utf-8')
        storage_path = os.path.join(self.storage_root, asset_group_id_str)
        if not os.path.exists(storage_path):
            os.makedirs(storage_path, exist_ok=True)
        path = os.path.join(storage_path, binascii.b2a_hex(asset_id).decode('utf-8'))
        if not do_overwrite and os.path.exists(path):
            return False
        with open(path, 'wb') as f:
            try:
                f.write(content)
            except:
                return False
        return os.path.exists(path)

    def get_in_storage(self, asset_group_id, asset_id):
        """Get the asset file with the asset_id from local storage

        Args:
            asset_group_id (bytes): asset_group_id of the asset
            asset_id (bytes): asset_id of the asset
        Returns:
            bytes or None: the file content
        """
        asset_group_id_str = binascii.b2a_hex(asset_group_id).decode('utf-8')
        storage_path = os.path.join(self.storage_root, asset_group_id_str)
        if not os.path.exists(storage_path):
            return None
        path = os.path.join(storage_path, binascii.b2a_hex(asset_id).decode('utf-8'))
        if not os.path.exists(path):
            return None
        try:
            with open(path, 'rb') as f:
                content = f.read()
            return content
        except:
            self.logger.error(traceback.format_exc())
            return None

    def _remove_in_storage(self, asset_group_id, asset_id):
        """Delete asset file

        Args:
            asset_group_id (bytes): asset_group_id of the asset
            asset_id (bytes): asset_id of the asset
        """
        #print("_remove_in_storage: for asset_id =", asset_id.hex())
        asset_group_id_str = binascii.b2a_hex(asset_group_id).decode('utf-8')
        storage_path = os.path.join(self.storage_root, asset_group_id_str)
        if not os.path.exists(storage_path):
            return
        path = os.path.join(storage_path, binascii.b2a_hex(asset_id).decode('utf-8'))
        if not os.path.exists(path):
            return
        os.remove(path)

    def process_message(self, msg):
        """Process received message

        Args:
            msg (dict): received message
        """
        if KeyType.infra_command not in msg:
            return

        if msg[KeyType.infra_command] == DataHandler.REQUEST_REPLICATION_INSERT:
            self.stats.update_stats_increment("data_handler", "REQUEST_REPLICATION_INSERT", 1)
            self.insert_transaction(msg[KeyType.transaction_data],
                                    asset_files=msg.get(KeyType.all_asset_files, None), no_replication=True)

        elif msg[KeyType.infra_command] == DataHandler.RESPONSE_REPLICATION_INSERT:
            self.stats.update_stats_increment("data_handler", "RESPONSE_REPLICATION_INSERT", 1)
            pass

        elif msg[KeyType.infra_command] == DataHandler.REQUEST_SEARCH:
            self.stats.update_stats_increment("data_handler", "REQUEST_SEARCH", 1)
            ret = self.search_transaction(msg[KeyType.transaction_id])
            msg[KeyType.infra_command] = DataHandler.RESPONSE_SEARCH
            if ret is None or len(ret) == 0:
                msg[KeyType.result] = False
                msg[KeyType.reason] = "Not found"
            else:
                msg[KeyType.result] = True
                msg[KeyType.transaction_data] = ret[0][1]
            self.networking.send_message_in_network(nodeinfo=None, payload_type=PayloadType.Type_any,
                                                    domain_id=self.domain_id, msg=msg)

        elif msg[KeyType.infra_command] == DataHandler.RESPONSE_SEARCH:
            self.stats.update_stats_increment("data_handler", "RESPONSE_SEARCH", 1)
            if msg[KeyType.result]:
                self.insert_transaction(msg[KeyType.transaction_data])

        elif msg[KeyType.infra_command] == DataHandler.NOTIFY_INSERTED:
            self.stats.update_stats_increment("data_handler", "NOTIFY_INSERTED", 1)
            if KeyType.transaction_id not in msg or KeyType.asset_group_ids not in msg:
                return
            transaction_id = msg[KeyType.transaction_id]
            asset_group_ids = msg[KeyType.asset_group_ids]
            self.core.send_inserted_notification(self.domain_id, asset_group_ids, transaction_id,
                                                 only_registered_user=True)

        elif msg[KeyType.infra_command] == DataHandler.REPAIR_TRANSACTION_DATA:
            self.networking.domains[self.domain_id]['repair'].put_message(msg)

        elif msg[KeyType.infra_command] == DataHandler.REPLICATION_CROSS_REF:
            transaction_id = msg[KeyType.transaction_id]
            outer_domain_id = msg[KeyType.outer_domain_id]
            txid_having_cross_ref = msg[KeyType.txid_having_cross_ref]
            self.insert_cross_ref(transaction_id, outer_domain_id, txid_having_cross_ref, no_replication=True)


class DataHandlerDomain0(DataHandler):
    """Data handler for domain_global_0"""
    def __init__(self, networking=None, config=None, workingdir=None, domain_id=None, loglevel="all", logname=None):
        pass

    def exec_sql(self, sql, *args):
        pass

    def get_asset_info(self, txobj):
        pass

    def _get_topology_info(self, txobj):
        pass

    def insert_transaction(self, txdata, txobj=None, asset_files=None, no_replication=False):
        return True

    def _send_replication_to_other_cores(self, txdata, asset_files=None):
        pass

    def remove(self, transaction_id):
        pass

    def search_transaction(self, transaction_id=None, asset_group_id=None, asset_id=None, user_id=None, count=1):
        return None, None

    def search_transaction_topology(self, transaction_id, reverse_link=False):
        return None

    def store_in_storage(self, asset_group_id, asset_id, content):
        return True

    def get_in_storage(self, asset_group_id, asset_id):
        return None

    def _remove_in_storage(self, asset_group_id, asset_id):
        pass

    def process_message(self, msg):
        pass


class DbAdaptor:
    """Base class for DB adaptor"""
    def __init__(self, handler=None, db_name=None, db_num=0, loglevel="all", logname=None):
        self.handler = handler
        self.db = None
        self.db_cur = None
        self.db_name = db_name
        self.db_num = db_num
        self.placeholder = ""
        self.logger = logger.get_logger(key="db_adaptor", level=loglevel, logname=logname)

    def open_db(self):
        """Open the DB"""
        pass

    def create_table(self, tbl, tbl_definition, primary_key=0, indices=[]):
        """Create a table"""
        pass

    def check_table_existence(self, tblname):
        """Check whether the table exists or not"""
        pass

    def get_version(self):
        """get_version of the DB

        Returns:
            str: version string
        """
        if len(self.check_table_existence("version_table")) == 0:
            return "ver=1"
        ret = self.handler.exec_sql(db_num=self.db_num, sql="SELECT version FROM version_table;")
        if ret is None or len(ret) == 0:
            return "ver=1"
        return ret[0][0]

    def update_table_def(self, from_ver):
        """Update table definition"""
        self.create_table("version_table", version_tbl_definition)
        ret = self.handler.exec_sql(db_num=self.db_num, sql="INSERT INTO version_table (version) VALUES (\"%s\");" % DB_VERSION, commit=True)
        if ret is None:
            print("XXXX Cannot create version_table in DB")
            sys.exit(1)
        if from_ver == "ver=1":
            self.create_ver2_column()

    def create_ver2_column(self):
        """Create column for version 2 meta table (add timestamp in asset_info_table)"""
        try:
            self.db_cur.execute("ALTER TABLE asset_info_table ADD COLUMN timestamp BIGINT;")
            self.db.commit()
        except:
            pass


class SqliteAdaptor(DbAdaptor):
    """DB adaptor for SQLite3"""
    def __init__(self, handler=None, db_name=None, loglevel="all", logname=None):
        super(SqliteAdaptor, self).__init__(handler=handler, db_name=db_name, loglevel=loglevel, logname=logname)
        self.placeholder = "?"

    def open_db(self):
        """Open the DB (create DB file if not exists)"""
        import sqlite3
        self.db = sqlite3.connect(self.db_name, isolation_level=None)
        self.db_cur = self.db.cursor()

    def create_table(self, tbl, tbl_definition, primary_key=0, indices=[]):
        """Create a table

        Args:
            tbl (str): table name
            tbl_definition (list): schema of the table [["column_name", "data type"],["colmun_name", "data type"],,]
            primary_key (int): index (column) of the primary key of the table
            indices (list): list of indices to create index
        """
        if len(self.check_table_existence(tbl)) > 0:
            return False
        sql = "CREATE TABLE %s " % tbl
        sql += "("
        sql += ", ".join(["%s %s" % (d[0],d[1]) for d in tbl_definition])
        sql += ", PRIMARY KEY ("+tbl_definition[primary_key][0]+")"
        sql += ");"
        self.handler.exec_sql(sql=sql, commit=True)
        for idx in indices:
            self.handler.exec_sql(sql="CREATE INDEX %s_idx_%d ON %s (%s);" % (tbl, idx, tbl, tbl_definition[idx][0]),
                                  commit=True)
        return True

    def check_table_existence(self, tblname):
        """Check whether the table exists or not"""
        return self.handler.exec_sql(sql="SELECT * FROM sqlite_master WHERE type='table' AND name=?", args=(tblname,))


class MysqlAdaptor(DbAdaptor):
    """DB adaptor for MySQL"""
    def __init__(self, handler=None, db_name=None, db_num=None, server_info=None, loglevel="all", logname=None):
        super(MysqlAdaptor, self).__init__(handler, db_name, db_num, loglevel, logname)
        self.placeholder = "%s"
        self.db_addr = server_info[0]
        self.db_port = server_info[1]
        self.db_user = server_info[2]
        self.db_pass = server_info[3]

    def open_db(self):
        """Open the DB"""
        import mysql.connector
        self.db = mysql.connector.connect(
            host=self.db_addr,
            port=self.db_port,
            db=self.db_name,
            user=self.db_user,
            password=self.db_pass,
            charset='utf8'
        )
        self.db_cur = self.db.cursor(buffered=True)

    def create_table(self, tbl, tbl_definition, primary_key=0, indices=[]):
        """Create a table

        Args:
            tbl (str): table name
            tbl_definition (list): schema of the table [["column_name", "data type"],["colmun_name", "data type"],,]
            primary_key (int): index (column) of the primary key of the table
            indices (list): list of indices to create index
        """
        if len(self.check_table_existence(tbl)) == 1:
            return False
        sql = "CREATE TABLE %s " % tbl
        sql += "("
        defs = list()
        for d in tbl_definition:
            if d[0] == "id":
                defs.append("%s %s AUTO_INCREMENT NOT NULL" % (d[0], d[1]))
            else:
                defs.append("%s %s" % (d[0], d[1]))
        sql += ",".join(defs)
        if tbl_definition[primary_key][1] in ["BLOB", "TEXT"]:
            sql += ", PRIMARY KEY (%s(32))" % tbl_definition[primary_key][0]
        else:
            sql += ", PRIMARY KEY (%s)" % tbl_definition[primary_key][0]
        sql += ") CHARSET=utf8;"
        self.handler.exec_sql(db_num=self.db_num, sql=sql, commit=True)
        for idx in indices:
            if tbl_definition[idx][1] in ["BLOB", "TEXT"]:
                self.handler.exec_sql(db_num=self.db_num, sql="ALTER TABLE %s ADD INDEX (%s(32));"
                                                              % (tbl, tbl_definition[idx][0]), commit=True)
            else:
                self.handler.exec_sql(db_num=self.db_num, sql="ALTER TABLE %s ADD INDEX (%s);"
                                                              % (tbl, tbl_definition[idx][0]), commit=True)
        return True

    def check_table_existence(self, tblname):
        """Check whether the table exists or not"""
        sql = "show tables from %s like '%s';" % (self.db_name, tblname)
        return self.handler.exec_sql(db_num=self.db_num, sql=sql)
