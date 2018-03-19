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
import hashlib
import os
import sys
sys.path.extend(["../../", os.path.abspath(os.path.dirname(__file__))])
from bbc1.core.bbc_types import InfraMessageCategory
from bbc1.core.bbc_stats import BBcStats
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
    REPLICATION_ALL = 0
    REPLICATION_P2P = 1
    REPLICATION_EXT = 2
    REQUEST_REPLICATION_INSERT = to_2byte(0)
    RESPONSE_REPLICATION_INSERT = to_2byte(1)
    REQUEST_SEARCH = to_2byte(2)
    RESPONSE_SEARCH = to_2byte(3)
    NOTIFY_INSERTED = to_2byte(4)

    def __init__(self, network=None, config=None, workingdir=None, domain_id=None, loglevel="all", logname=None):
        if network is not None:
            self.network = network
            self.core = network.core
            self.stats = network.core.stats
        else:
            self.stats = BBcStats()
        self.logger = logger.get_logger(key="data_handler", level=loglevel, logname=logname)
        self.domain_id = domain_id
        self.domain_id_str = bbclib.convert_id_to_string(domain_id)
        self.config = config
        self.working_dir = workingdir
        self.storage_root = os.path.join(self.working_dir, self.domain_id_str)
        if not os.path.exists(self.storage_root):
            os.makedirs(self.storage_root, exist_ok=True)
        self.use_external_storage = self.storage_setup()
        self.replication_strategy = DataHandler.REPLICATION_ALL
        self.db_adaptors = list()
        self.dbs = list()
        self.db_setup()

    def db_setup(self):
        """
        Setup DB
        :return:
        """
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
            db.create_table('transaction_table', transaction_tbl_definition, primary_key=0, indices=[0])
            db.create_table('asset_info_table', asset_info_definition, primary_key=0, indices=[0, 1, 2, 3, 4])
            db.create_table('topology_table', topology_info_definition, primary_key=0, indices=[0, 1, 2])

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
        for d in self.db_adaptors:
            d.db_cur.close()
            d.db.close()

    def exec_sql(self, db_num=0, sql=None, args=()):
        """
        Execute sql sentence
        :param db_num:
        :param sql:
        :param args:
        :return:
        """
        self.stats.update_stats_increment("data_handler", "exec_sql", 1)
        #print("sql=", sql)
        #if len(args) > 0:
        #    print("args=", args)
        try:
            db_num = 0 if db_num >= len(self.db_adaptors) else db_num
            if len(args) > 0:
                ret = self.db_adaptors[db_num].db_cur.execute(sql, args)
            else:
                ret = self.db_adaptors[db_num].db_cur.execute(sql)
            self.db_adaptors[db_num].db.commit()
        except:
            self.logger.error(traceback.format_exc())
            traceback.print_exc()
            self.stats.update_stats_increment("data_handler", "fail_exec_sql", 1)
            return None
        if ret is None:
            return []
        else:
            return list(ret)

    def exec_sql_fetchall(self, db_num=0, sql=None, args=()):
        """
        Execute sql sentence
        :param db_num:
        :param sql:
        :param args:
        :return:
        """
        self.stats.update_stats_increment("data_handler", "exec_sql", 1)
        #print("sql=", sql)
        try:
            db_num = 0 if db_num >= len(self.db_adaptors) else db_num
            if len(args) > 0:
                self.db_adaptors[db_num].db_cur.execute(sql, args)
            else:
                self.db_adaptors[db_num].db_cur.execute(sql)
            ret = self.db_adaptors[db_num].db_cur.fetchall()
        except:
            self.logger.error(traceback.format_exc())
            traceback.print_exc()
            self.stats.update_stats_increment("data_handler", "fail_exec_sql", 1)
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
        self.stats.update_stats_increment("data_handler", "insert_transaction", 1)
        if txobj is None:
            txobj = self.core.validate_transaction(txdata, asset_files=asset_files)
            if txobj is None:
                return None

        inserted_count = 0
        for i in range(len(self.db_adaptors)):
            ret = self.exec_sql(db_num=i,
                                sql="INSERT INTO transaction_table VALUES (%s,%s)" % (self.db_adaptors[0].placeholder,
                                                                                      self.db_adaptors[0].placeholder),
                                args=(txobj.transaction_id, txdata))
            if ret is None:
                continue
            inserted_count += 1

            for asset_group_id, asset_id, user_id, fileflag, filedigest in self.get_asset_info(txobj):
                self.exec_sql(db_num=i,
                              sql="INSERT INTO asset_info_table(transaction_id, asset_group_id, asset_id, user_id) "
                                "VALUES (%s, %s, %s, %s)" % (self.db_adaptors[0].placeholder, self.db_adaptors[0].placeholder,
                                                             self.db_adaptors[0].placeholder, self.db_adaptors[0].placeholder),
                                args=(txobj.transaction_id, asset_group_id, asset_id, user_id))
            for tx_to, tx_from in self.get_topology_info(txobj):
                self.exec_sql(db_num=i,
                              sql="INSERT INTO topology_table(tx_to, tx_from) VALUES (%s, %s)" %
                                (self.db_adaptors[0].placeholder, self.db_adaptors[0].placeholder),
                              args=(tx_to, tx_from))

        if inserted_count == 0:
            return None

        asset_group_ids = set()
        for asset_group_id, asset_id, user_id, fileflag, filedigest in self.get_asset_info(txobj):
            asset_group_ids.add(asset_group_id)
            if not self.use_external_storage and asset_files is not None and asset_id in asset_files:
                self.store_in_storage(asset_group_id, asset_id, asset_files[asset_id])

        if not no_replication and self.replication_strategy != DataHandler.REPLICATION_EXT:
            self.send_replication_to_other_cores(txdata, asset_files)

        return asset_group_ids

    def send_replication_to_other_cores(self, txdata, asset_files=None):
        """
        Send replication of transaction data
        :param txdata:
        :return:
        """
        msg = {
            KeyType.domain_id: self.domain_id,
            KeyType.infra_msg_type: InfraMessageCategory.CATEGORY_DATA,
            KeyType.infra_command: DataHandler.REQUEST_REPLICATION_INSERT,
            KeyType.transaction_data: txdata,
        }
        if asset_files is not None:
            msg[KeyType.all_asset_files] = asset_files
        if self.replication_strategy == DataHandler.REPLICATION_ALL:
            self.network.broadcast_message_in_network(domain_id=self.domain_id,
                                                      payload_type=PayloadType.Type_msgpack, msg=msg)
        elif self.replication_strategy == DataHandler.REPLICATION_P2P:
            pass  # TODO: implement (destinations determined by TopologyManager)

    def remove(self, transaction_id):
        """
        Delete data
        :param transaction_id:
        :return:
        """
        if transaction_id is None:
            return
        txdata = self.exec_sql_fetchall(sql="SELECT * FROM transaction_table WHERE transaction_id = %s" %
                                            self.db_adaptors[0].placeholder, args=(transaction_id,))
        txobj = bbclib.BBcTransaction(deserialize=txdata[0][1])

        for i in range(len(self.db_adaptors)):
            self.exec_sql(
                db_num=i,
                sql="DELETE FROM transaction_table WHERE transaction_id = %s" % self.db_adaptors[0].placeholder,
                args=(transaction_id,))
            for asset_group_id, asset_id, user_id, fileflag, filedigest in self.get_asset_info(txobj):
                self.exec_sql(
                    db_num=i,
                    sql="DELETE FROM asset_info_table WHERE asset_group_id = %s AND asset_id = %s AND user_id = %s" %
                        (self.db_adaptors[0].placeholder,self.db_adaptors[0].placeholder,self.db_adaptors[0].placeholder),
                    args=(asset_group_id, asset_id, user_id))
                if fileflag:
                    self.remove_in_storage(asset_group_id, asset_id)
            for tx_to, tx_from in self.get_topology_info(txobj):
                self.exec_sql(
                    db_num=i,
                    sql="DELETE FROM topology_table WHERE tx_to = %s AND tx_from = %s" %
                        (self.db_adaptors[0].placeholder,self.db_adaptors[0].placeholder),
                    args=(tx_to, tx_from))

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
            txinfo = self.exec_sql_fetchall(sql="SELECT * FROM transaction_table WHERE transaction_id = %s" %
                                                self.db_adaptors[0].placeholder, args=(transaction_id,))
            if len(txinfo) == 0:
                return None, None
        else:
            sql = "SELECT * from asset_info_table WHERE "
            conditions = list()
            if asset_group_id is not None:
                conditions.append("asset_group_id = %s " % self.db_adaptors[0].placeholder)
            if asset_id is not None:
                conditions.append("asset_id = %s " % self.db_adaptors[0].placeholder)
            if user_id is not None:
                conditions.append("user_id = %s " % self.db_adaptors[0].placeholder)
            sql += "AND ".join(conditions) + "ORDER BY id DESC"
            if count > 0:
                if count > 20:
                    count = 20
                sql += " limit %d" % count
            sql += ";"
            args = list(filter(lambda a: a is not None, (asset_group_id, asset_id, user_id)))
            ret = self.exec_sql_fetchall(sql=sql, args=args)
            txinfo = list()
            for record in ret:
                tx = self.exec_sql_fetchall(sql="SELECT * FROM transaction_table WHERE transaction_id = %s" %
                                                self.db_adaptors[0].placeholder, args=(record[1],))
                if tx is not None and len(tx) == 1:
                    txinfo.append(tx[0])

        result_txobj = list()
        txid_list = dict()
        result_asset_files = dict()
        compromised_tx = list()
        compromised_asset_files = list()
        for txid, txdata in txinfo:
            if txid in txid_list:
                continue
            txid_list[txid] = True
            txobj = bbclib.BBcTransaction()
            txobj.deserialize(txdata)
            for sig in txobj.signatures:
                if not sig.verify(txid):
                    compromised_tx.append(txid)
            result_txobj.append(txobj)
            for asset_group_id, asset_id, user_id, fileflag, filedigest in self.get_asset_info(txobj):
                if fileflag:
                    assetfile = self.get_in_storage(asset_group_id, asset_id)
                    if hashlib.sha256(assetfile).digest() == filedigest:
                        result_asset_files[asset_id] = assetfile
                    else:
                        compromised_asset_files.append(asset_id)
        if len(compromised_tx) == 0 and len(compromised_asset_files) == 0:
            return result_txobj, result_asset_files
        # TODO: implement finding correct transaction data and asset file
        print(len(compromised_tx), len(compromised_asset_files))
        return None, None

    def search_transaction_topology(self, transaction_id, reverse_link=False):
        """
        Search in topology info
        :param transaction_id:
        :return:
        """
        if transaction_id is None:
            return None
        if reverse_link:
            return self.exec_sql_fetchall(sql="SELECT * FROM topology_table WHERE tx_from = %s" %
                                              self.db_adaptors[0].placeholder, args=(transaction_id,))

        else:
            return self.exec_sql_fetchall(sql="SELECT * FROM topology_table WHERE tx_to = %s" %
                                              self.db_adaptors[0].placeholder, args=(transaction_id,))

    def store_in_storage(self, asset_group_id, asset_id, content):
        """
        Store data in local storage
        :param asset_group_id
        :param asid:
        :param content:
        :return:
        """
        self.stats.update_stats_increment("data_handler", "store_in_storage", 1)
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
            self.network.send_message_in_network(nodeinfo=None, payload_type=PayloadType.Type_msgpack,
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


class DataHandlerDomain0(DataHandler):
    def __init__(self, network=None, config=None, workingdir=None, domain_id=None, loglevel="all", logname=None):
        pass

    def close_db(self):
        pass

    def exec_sql(self, sql, *args):
        pass

    def get_asset_info(self, txobj):
        pass

    def get_topology_info(self, txobj):
        pass

    def insert_transaction(self, txdata, txobj=None, asset_files=None, no_replication=False):
        return True

    def send_replication_to_other_cores(self, txdata, asset_files=None):
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

    def remove_in_storage(self, asset_group_id, asset_id):
        pass

    def process_message(self, msg):
        pass


class DbAdaptor:
    def __init__(self, handler=None, db_name=None, db_num=0, loglevel="all", logname=None):
        self.handler = handler
        self.db = None
        self.db_cur = None
        self.db_name = db_name
        self.db_num = db_num
        self.placeholder = ""
        self.logger = logger.get_logger(key="db_adaptor", level=loglevel, logname=logname)

    def open_db(self):
        pass

    def create_table(self, tbl, tbl_definition, primary_key=0, indices=[]):
        pass

    def check_table_existence(self, tblname):
        pass


class SqliteAdaptor(DbAdaptor):
    def __init__(self, handler=None, db_name=None, loglevel="all", logname=None):
        super(SqliteAdaptor, self).__init__(handler=handler, db_name=db_name, loglevel=loglevel, logname=logname)
        self.placeholder = "?"

    def open_db(self):
        import sqlite3
        self.db = sqlite3.connect(self.db_name, isolation_level=None)
        self.db_cur = self.db.cursor()

    def create_table(self, tbl, tbl_definition, primary_key=0, indices=[]):
        if len(self.check_table_existence(tbl)) > 0:
            return
        sql = "CREATE TABLE %s " % tbl
        sql += "("
        sql += ", ".join(["%s %s" % (d[0],d[1]) for d in tbl_definition])
        sql += ", PRIMARY KEY ("+tbl_definition[primary_key][0]+")"
        sql += ");"
        self.handler.exec_sql(sql=sql)
        for idx in indices:
            self.handler.exec_sql(sql="CREATE INDEX %s_idx_%d ON %s (%s);" % (tbl, idx, tbl, tbl_definition[idx][0]))

    def check_table_existence(self, tblname):
        return self.handler.exec_sql_fetchall(sql="SELECT * FROM sqlite_master WHERE type='table' AND name=?", args=(tblname,))


class MysqlAdaptor(DbAdaptor):
    def __init__(self, handler=None, db_name=None, db_num=None, server_info=None, loglevel="all", logname=None):
        super(MysqlAdaptor, self).__init__(handler, db_name, db_num, loglevel, logname)
        self.placeholder = "%s"
        self.db_addr = server_info[0]
        self.db_port = server_info[1]
        self.db_user = server_info[2]
        self.db_pass = server_info[3]

    def open_db(self):
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
        if len(self.check_table_existence(tbl)) == 1:
            return
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
        self.handler.exec_sql(db_num=self.db_num, sql=sql)
        for idx in indices:
            if tbl_definition[idx][1] in ["BLOB", "TEXT"]:
                self.handler.exec_sql(db_num=self.db_num, sql="ALTER TABLE %s ADD INDEX (%s(32));" % (tbl, tbl_definition[idx][0]))
            else:
                self.handler.exec_sql(db_num=self.db_num, sql="ALTER TABLE %s ADD INDEX (%s);" % (tbl, tbl_definition[idx][0]))

    def check_table_existence(self, tblname):
        sql = "show tables from %s like '%s';" % (self.db_name, tblname)
        return self.handler.exec_sql_fetchall(db_num=self.db_num, sql=sql)
