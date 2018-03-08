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
from bbc1.core.bbc_types import InfraMessageCategory
from bbc1.common import bbclib
from bbc1.common.message_key_types import to_2byte, PayloadType, KeyType
from bbc1.common import logger


transaction_tbl_definition = [
    ["transaction_id", "BLOB"], ["transaction_data", "BLOB"],
]

asset_info_definition = [
    ["id", "INTEGER"],
    ["transaction_id", "BLOB"], ["asset_group_id", "BLOB"], ["asset_id", "BLOB"], ["user_id", "BLOB"],
]

topology_info_definition = [
    ["id", "INTEGER"], ["tx_to", "BLOB"], ["tx_from", "BLOB"]
]


class DataHandler:
    """
    Handle message for data
    """
    REQUEST_REPLICATION_INSERT = to_2byte(0)
    RESPONSE_REPLICATION_INSERT = to_2byte(1)
    REQUEST_SEARCH = to_2byte(2)
    RESPONSE_SEARCH = to_2byte(3)

    def __init__(self, network=None, config=None, workingdir=None, domain_id=None, loglevel="all", logname=None):
        if network is not None:
            self.network = network
            self.core = network.core
        self.logger = logger.get_logger(key="data_handler", level=loglevel, logname=logname)
        self.domain_id = domain_id
        self.domain_id_str = bbclib.convert_id_to_string(domain_id)
        self.config = config
        self.working_dir = workingdir
        self.storage_root = os.path.join(self.working_dir, self.domain_id_str)
        if not os.path.exists(self.storage_root):
            os.makedirs(self.storage_root, exist_ok=True)
        self.use_external_storage = self.storage_setup()
        self.send_copy_to_all_neighbors = None
        self.db_adaptor = None
        self.db_cur = None
        self.dbs = list()
        self.db_setup()

    def db_setup(self):
        """
        Setup DB
        :return:
        """
        dbconf = self.config['db']
        if dbconf['send_copy_to'] == 'all':
            self.send_copy_to_all_neighbors = "all"
        elif dbconf['send_copy_to'] == 'custom':
            self.send_copy_to_all_neighbors = "custom"
        db_type = dbconf.get("db_type", "sqlite")
        if db_type == "sqlite":
            db_name = dbconf.get("db_name", "bbc1_db.sqlite")
            self.db_adaptor = SqliteAdaptor(self, db_name=os.path.join(self.storage_root, db_name))
        elif db_type == "mysql":
            servers = list()
            for c in dbconf['servers']:
                db_addr = dbconf.get("db_addr", "127.0.0.1")
                db_port = dbconf.get("db_port", 3306)
                db_user = dbconf.get("db_user", "user")
                db_pass = dbconf.get("db_pass", "password")
                servers.append((db_addr, db_port, db_user, db_pass))
            self.db_adaptor = MysqlAdaptor(self, servers=servers)
        if self.db_adaptor is None:
            return
        self.db_adaptor.open_db()
        self.db_adaptor.create_table('transaction_table', transaction_tbl_definition, primary_key=0, indices=[0])
        self.db_adaptor.create_table('asset_info_table', asset_info_definition, primary_key=0, indices=[0, 1, 2, 3])
        self.db_adaptor.create_table('topology_table', topology_info_definition, primary_key=0, indices=[0, 1])

    def storage_setup(self):
        if self.config['storage']['type'] == "external":
            return True
        if 'root' in self.config['storage'] and self.config['storage']['root'].startswith("/"):
            self.storage_root = os.path.join(self.config['storage']['root'], self.domain_id_str)
        else:
            self.storage_root = os.path.join(self.working_dir, self.domain_id_str)
        os.makedirs(self.storage_root, exist_ok=True)
        return False

    def close_db(self):
        """
        (internal use) close DB
        """
        self.db_cur.close()
        self.db_adaptor.db.close()

    def exec_sql(self, sql, *args):
        """
        Execute sql sentence
        :param sql:
        :param args:
        :return:
        """
        try:
            if len(args) > 0:
                ret = self.db_cur.execute(sql, (*args,))
            else:
                ret = self.db_cur.execute(sql)
        except:
            self.logger.error(traceback.format_exc())
            return None
        if ret is not None:
            ret = list(ret)
        return ret

    def get_asset_info(self, txobj):
        """
        Retrieve asset information from transaction object
        :param txobj:
        :return:
        """
        info = list()
        for idx, evt in enumerate(txobj.events):
            if evt.asset is not None:
                info.append((evt.asset_group_id, evt.asset.asset_id, evt.asset.user_id, evt.asset.asset_file_size>0))
        for idx, rtn in enumerate(txobj.relations):
            if rtn.asset is not None:
                info.append((rtn.asset_group_id, rtn.asset.asset_id, rtn.asset.user_id, rtn.asset.asset_file_size>0))
        return info

    def get_topology_info(self, txobj):
        """
        Retrieve topology information from transaction object
        :param txobj:
        :return:
        """
        info = list()
        for reference in txobj.references:
            info.append((txobj.transaction_id, reference.transaction_id))
        for idx, rtn in enumerate(txobj.relations):
            for pt in rtn.pointers:
                info.append((txobj.transaction_id, pt.transaction_id))
        return info

    def insert_transaction(self, txdata, txobj=None, asset_files=None, no_replication=False):
        """
        Insert transaction data and its asset files
        :param txdata:
        :param txobj:
        :param asset_files:
        :return:
        """
        if txobj is None:
            txobj = self.core.validate_transaction(txdata, asset_files=asset_files)
            if txobj is None:
                return False

        ret = self.exec_sql("INSERT INTO transaction_table VALUES (?, ?)", txobj.transaction_id, txdata)
        if ret is None:
            return False

        if not no_replication:
            self.send_replication_to_other_cores(txdata, asset_files)

        rollback_asset = list()
        rollback_asset_file = list()
        rollback_flag = False
        for asset_group_id, asset_id, user_id, fileflag in self.get_asset_info(txobj):
            ret = self.exec_sql("INSERT INTO asset_info_table(transaction_id, asset_group_id, asset_id, user_id) "
                                "VALUES (?, ?, ?, ?)",
                                txobj.transaction_id, asset_group_id, asset_id, user_id)
            if ret is not None:
                rollback_asset.append((asset_group_id, asset_id, user_id))
            else:
                rollback_flag = True
                break
            if not self.use_external_storage and asset_files is not None and asset_id in asset_files:
                if self.store_in_storage(asset_group_id, asset_id, asset_files[asset_id]):
                    rollback_asset_file.append((asset_group_id, asset_id))
                else:
                    rollback_flag = True
                    break

        rollback_topology = list()
        if not rollback_flag:
            for tx_to, tx_from in self.get_topology_info(txobj):
                ret = self.exec_sql("INSERT INTO topology_table(tx_to, tx_from) VALUES (?, ?)", tx_to, tx_from)
                if ret is not None:
                    rollback_topology.append((tx_to, tx_from))
                else:
                    rollback_flag = True
                    break

        if rollback_flag:
            self.exec_sql("DELETE FROM transaction_table WHERE transaction_id = ?", txobj.transaction_id)
            for asset_group_id, asset_id, user_id in rollback_asset:
                self.exec_sql("DELETE FROM asset_info_table WHERE asset_group_id = ? AND asset_id = ? AND user_id = ?",
                              asset_group_id, asset_id, user_id)
            for tx_to, tx_from in rollback_topology:
                self.exec_sql("DELETE FROM topology_table WHERE tx_to = ? AND tx_from = ?", tx_to, tx_from)
            if not self.use_external_storage:
                for asset_group_id, asset_id in rollback_asset_file:
                    self.remove_in_storage(asset_group_id, asset_id)
            return False
        return True

    def send_replication_to_other_cores(self, txdata, asset_files=None):
        """
        Send replication of transaction data
        :param txdata:
        :return:
        """
        if self.send_copy_to_all_neighbors is None:
            return
        msg = {
            KeyType.domain_id: self.domain_id,
            KeyType.infra_msg_type: InfraMessageCategory.CATEGORY_DATA,
            KeyType.command: DataHandler.REQUEST_REPLICATION_INSERT,
            KeyType.transaction_data: txdata,
        }
        if asset_files is not None:
            msg[KeyType.all_asset_files] = asset_files
        if self.send_copy_to_all_neighbors == "all":
            self.network.broadcast_message_in_network(domain_id=self.domain_id,
                                                      payload_type=PayloadType.Type_msgpack, msg=msg)
        elif self.send_copy_to_all_neighbors == "custom":
            pass  # TODO: implement (destinations determined by TopologyManager)

    def remove(self, transaction_id):
        """
        Delete data
        :param transaction_id:
        :return:
        """
        if transaction_id is None:
            return
        txdata = self.exec_sql("SELECT * FROM transaction_table WHERE transaction_id = ?", transaction_id)
        txobj = bbclib.BBcTransaction(deserialize=txdata[0][1])

        self.exec_sql("DELETE FROM transaction_table WHERE transaction_id = ?", transaction_id)
        for asset_group_id, asset_id, user_id, fileflag in self.get_asset_info(txobj):
            self.exec_sql("DELETE FROM asset_info_table WHERE asset_group_id = ? AND asset_id = ? AND user_id = ?",
                          asset_group_id, asset_id, user_id)
            if fileflag:
                self.remove_in_storage(asset_group_id, asset_id)
        for tx_to, tx_from in self.get_topology_info(txobj):
            self.exec_sql("DELETE FROM topology_table WHERE tx_to = ? AND tx_from = ?", tx_to, tx_from)

    def search_transaction(self, transaction_id=None, asset_group_id=None, asset_id=None, user_id=None, count=1):
        """
        Search transaction data
        :param transaction_id:
        :param asset_group_id:
        :param asset_id:
        :param user_id:
        :param count:
        :return:
        """
        if transaction_id is not None:
            txinfo = self.exec_sql("SELECT * FROM transaction_table WHERE transaction_id = ?", transaction_id)
            if len(txinfo) == 0:
                return None, None
        else:
            sql = "SELECT * from asset_info_table WHERE "
            conditions = list()
            if asset_group_id is not None:
                conditions.append("asset_group_id = ? ")
            if asset_id is not None:
                conditions.append("asset_id = ? ")
            if user_id is not None:
                conditions.append("user_id = ? ")
            sql += "AND ".join(conditions) + "ORDER BY id DESC"
            if count > 0:
                if count > 20:
                    count = 20
                sql += " limit %d" % count
            sql += ";"
            args = list(filter(lambda a: a is not None, (asset_group_id, asset_id, user_id)))
            ret = self.exec_sql(sql, *args)
            txinfo = list()
            for record in ret:
                tx = self.exec_sql("SELECT * FROM transaction_table WHERE transaction_id = ?", record[1])
                if tx is not None and len(tx) == 1:
                    txinfo.append(tx[0])

        result_txobj = list()
        txid_list = dict()
        result_asset_files = dict()
        for txid, txdata in txinfo:
            if txid in txid_list:
                continue
            txid_list[txid] = True
            txobj = bbclib.BBcTransaction()
            txobj.deserialize(txdata)
            for sig in txobj.signatures:
                if not sig.verify(txid):
                    return None  # TODO: データが改ざんされていた場合の対応（別のところから取ってくる?）
            result_txobj.append(txobj)
            for asset_group_id, asset_id, user_id, fileflag in self.get_asset_info(txobj):
                if fileflag:
                    result_asset_files[asset_id] = self.get_in_storage(asset_group_id, asset_id)
        return result_txobj, result_asset_files

    def search_transaction_topology(self, transaction_id, reverse_link=False):
        """
        Search in topology info
        :param transaction_id:
        :return:
        """
        if transaction_id is None:
            return None
        if reverse_link:
            return self.exec_sql("SELECT * FROM topology_table WHERE tx_from = ?", transaction_id)
        else:
            return self.exec_sql("SELECT * FROM topology_table WHERE tx_to = ?", transaction_id)

    def store_in_storage(self, asset_group_id, asset_id, content):
        """
        Store data in local storage
        :param asset_group_id
        :param asid:
        :param content:
        :return:
        """
        asset_group_id_str = binascii.b2a_hex(asset_group_id).decode('utf-8')
        storage_path = os.path.join(self.storage_root, asset_group_id_str)
        if not os.path.exists(storage_path):
            os.makedirs(storage_path, exist_ok=True)
        path = os.path.join(storage_path, binascii.b2a_hex(asset_id).decode('utf-8'))
        if os.path.exists(path):
            return False
        with open(path, 'wb') as f:
            try:
                f.write(content)
            except:
                return False
        return os.path.exists(path)

    def get_in_storage(self, asset_group_id, asset_id):
        """
        Get the file with the asset_id from local storage
        :param asset_group_id
        :param asid:   file name
        :return:       the file content (None if not found)
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

    def remove_in_storage(self, asset_group_id, asset_id):
        """
        Delete asset file
        :param asset_group_id:
        :param asset_id:
        :return:
        """
        asset_group_id_str = binascii.b2a_hex(asset_group_id).decode('utf-8')
        storage_path = os.path.join(self.storage_root, asset_group_id_str)
        if not os.path.exists(storage_path):
            return
        path = os.path.join(storage_path, binascii.b2a_hex(asset_id).decode('utf-8'))
        if not os.path.exists(path):
            return
        os.remove(path)

    def process_message(self, msg):
        """
        (internal use) process received message
        :param msg:       the message body (already deserialized)
        :return:
        """
        if KeyType.command not in msg:
            return

        if msg[KeyType.command] == DataHandler.REQUEST_REPLICATION_INSERT:
            self.insert_transaction(msg[KeyType.transaction_data],
                                    asset_files=msg.get(KeyType.all_asset_files, None), no_replication=True)

        elif msg[KeyType.command] == DataHandler.RESPONSE_REPLICATION_INSERT:
            pass

        elif msg[KeyType.command] == DataHandler.REQUEST_SEARCH:
            ret = self.search_transaction(msg[KeyType.transaction_id])
            msg[KeyType.command] = DataHandler.RESPONSE_SEARCH
            if ret is None or len(ret) == 0:
                msg[KeyType.result] = False
                msg[KeyType.reason] = "Not found"
            else:
                msg[KeyType.result] = True
                msg[KeyType.transaction_data] = ret[0][1]
            self.network.send_message_in_network(nodeinfo=None, payload_type=PayloadType.Type_msgpack,
                                                 domain_id=self.domain_id, msg=msg)

        elif msg[KeyType.command] == DataHandler.RESPONSE_SEARCH:
            if msg[KeyType.result]:
                self.insert_transaction(msg[KeyType.transaction_data])


class DbAdaptor:
    def __init__(self, handler=None, db_name=None, servers=None, loglevel="all", logname=None):
        self.handler = handler
        self.db = None
        self.db_name = db_name
        self.servers = servers
        self.logger = logger.get_logger(key="db_adaptor", level=loglevel, logname=logname)

    def open_db(self):
        pass

    def create_table(self, tbl, tbl_definition, primary_key=0, indices=[]):
        pass

    def get_sql_table_existence_check(self, tblname):
        pass


class SqliteAdaptor(DbAdaptor):
    def __init__(self, handler=None, db_name=None, servers=None, loglevel="all", logname=None):
        super(SqliteAdaptor, self).__init__(handler, db_name, servers, loglevel, logname)

    def open_db(self):
        import sqlite3
        self.db = sqlite3.connect(self.db_name, isolation_level=None)
        self.handler.db_cur = self.db.cursor()

    def create_table(self, tbl, tbl_definition, primary_key=0, indices=[]):
        if len(self.check_table_existence(tbl)) > 0:
            return
        sql = "CREATE TABLE %s " % tbl
        sql += "("
        sql += ", ".join(["%s %s" % (d[0],d[1]) for d in tbl_definition])
        sql += ", PRIMARY KEY ("+tbl_definition[primary_key][0]+")"
        sql += ");"
        self.handler.exec_sql(sql)
        for idx in indices:
            self.handler.exec_sql("CREATE INDEX %s_idx_%d ON %s (%s);" % (tbl, idx, tbl, tbl_definition[idx][0]))

    def check_table_existence(self, tblname):
        return self.handler.exec_sql("SELECT * FROM sqlite_master WHERE type='table' AND name=?", tblname)


class MysqlAdaptor(DbAdaptor):
    def __init__(self, handler=None, db_name=None, servers=None, loglevel="all", logname=None):
        super(MysqlAdaptor, self).__init__(handler, db_name, servers, loglevel, logname)

    def open_db(self):
        pass

    def create_table(self, tbl, tbl_definition, primary_key=0, indices=[]):
        pass

    def get_sql_table_existence_check(self, tblname):
        pass
