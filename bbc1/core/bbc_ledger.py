# -*- coding: utf-8 -*-
import os
import sqlite3
import binascii

import sys
sys.path.extend(["../../"])
from bbc1.common import logger
from bbc1.core.bbc_types import ResourceType


transaction_tbl_definition = [
    ["transaction_id", "BLOB"], ["transaction_data", "BLOB"],
]

asset_info_definition = [
    ["id", "INTEGER"], ["transaction_id", "BLOB"], ["asset_group_id", "BLOB"],
    ["asset_id", "BLOB"], ["user_id", "BLOB"],
]

topology_info_definition = [
    ["id", "INTEGER"], ["transaction_id", "BLOB"], ["resource_type", "INTEGER"], ["resource_id", "BLOB"]
]


class BBcLedger:
    """
    Database manager
    SQL style only (for PoC alpha version) 
    """
    def __init__(self, config, dbtype="sqlite", loglevel="all", logname=None):
        """
        only support sqlite3

        :param dbtype:  type of database system
        """
        self.config = config
        conf = self.config.get_config()
        self.logger = logger.get_logger(key="bbc_ledger", level=loglevel, logname=logname)
        if 'ledger' not in conf:
            self.logger.error("No 'ledger' entry in config!!")
            os._exit(1)
        if 'type' not in conf['ledger']:
            self.logger.error("No 'ledger'.'type' entry in config!!")
            os._exit(1)
        if conf['ledger']['type'] != "sqlite3":
            self.logger.error("Currently, only sqlite3 is supported.")
            os._exit(1)
        self.dbtype = dbtype
        self.db_name = dict()
        self.db = dict()
        self.db_cur = dict()

    def add_domain(self, domain_id):
        """
        Add domain in the ledger

        :param domain_id:
        :return:
        """
        conf = self.config.get_config()
        self.db_name[domain_id] = dict()
        domain_id_str = binascii.b2a_hex(domain_id).decode()
        domain_dir = conf['workingdir'] + "/" + domain_id_str + "/"
        if not os.path.exists(domain_dir):
            os.mkdir(domain_dir, 0o777)
        self.db_name[domain_id]['transaction_db'] = domain_dir + \
                                                    conf['ledger'].get('transaction_db', "bbc_transaction.sqlite3")
        self.db_name[domain_id]['auxiliary_db'] = domain_dir + \
                                                  conf['ledger'].get('auxiliary_db', "bbc_aux.sqlite3")
        self.db[domain_id] = dict()
        self.db_cur[domain_id] = dict()
        self.create_table_in_db(domain_id, 'transaction_db', 'transaction_table',
                                transaction_tbl_definition, primary_key=0, indices=[0])
        self.create_table_in_db(domain_id, 'auxiliary_db', 'asset_info_table',
                                asset_info_definition, primary_key=0, indices=[1, 2, 3, 4])
        self.create_table_in_db(domain_id, 'auxiliary_db', 'topology_table',
                                topology_info_definition, primary_key=0, indices=[1, 2, 3])

    def open_db(self, domain_id, dbname):
        """
        (internal use) open DB

        :param domain_id:
        :param dbname:
        :return:
        """
        if domain_id not in self.db or domain_id not in self.db_cur:
            return
        self.db[domain_id][dbname] = sqlite3.connect(self.db_name[domain_id][dbname], isolation_level=None)
        self.db_cur[domain_id][dbname] = self.db[domain_id][dbname].cursor()

    def close_db(self, domain_id, dbname):
        """
        (internal use) close DB

        :param domain_id:
        :param dbname:
        :return:
        """
        if domain_id not in self.db or domain_id not in self.db_cur:
            return
        self.db_cur[domain_id][dbname].close()
        self.db[domain_id][dbname].close()

    def create_table_in_db(self, domain_id, dbname, tbl, tbl_definition, primary_key=0, indices=[]):
        """
        (internal use) Create a new table in a DB

        :param domain_id:
        :param dbname:
        :param tbl:
        :param tbl_definition:
        :param primary_keys:
        :param indices:
        :return:
        """
        if domain_id not in self.db or domain_id not in self.db_cur or domain_id not in self.db_name:
            return
        if self.check_table_existence(domain_id, dbname, tbl) is not None:
            return
        sql = "CREATE TABLE %s " % tbl
        sql += "("
        sql += ", ".join(["%s %s" % (d[0],d[1]) for d in tbl_definition])
        sql += ", PRIMARY KEY ("+tbl_definition[primary_key][0]+")"
        sql += ");"
        self.exec_sql(domain_id, dbname, sql)
        for idx in indices:
            self.exec_sql(domain_id, dbname, "CREATE INDEX %s_idx_%d ON %s (%s);" %
                          (tbl, idx, tbl, tbl_definition[idx][0]))

    def exec_sql_fetchone(self, domain_id, dbname, sql, *dat):
        """
        (internal use) Exec SQL and get one record

        :param domain_id:
        :param dbname:
        :param sql:
        :param dat:
        :return:
        """
        if domain_id not in self.db or domain_id not in self.db_cur or domain_id not in self.db_name:
            return None
        if dbname not in self.db[domain_id]:
            self.open_db(domain_id, dbname)
        if len(dat) > 0:
            ret = self.db_cur[domain_id][dbname].execute(sql, (*dat,)).fetchone()
        else:
            ret = self.db_cur[domain_id][dbname].execute(sql).fetchone()
        if ret is not None:
            ret = list(ret)
        return ret

    def exec_sql(self, domain_id, dbname, sql, *dat):
        """
        (internal use) Exec SQL and get all records

        :param domain_id:
        :param dbname:
        :param sql:
        :param dat:
        :return:
        """
        if domain_id not in self.db or domain_id not in self.db_cur or domain_id not in self.db_name:
            return None
        if dbname not in self.db[domain_id]:
            self.open_db(domain_id, dbname)
        if len(dat) > 0:
            ret = self.db_cur[domain_id][dbname].execute(sql, (*dat,))
        else:
            ret = self.db_cur[domain_id][dbname].execute(sql)
        if ret is not None:
            ret = list(ret)
        return ret

    def check_table_existence(self, domain_id, dbname, name):
        """
        (internal use) checking table existence

        :param domain_id:
        :param dbname:
        :param name: 
        :return: the corresponding record array or None
        """
        ret = self.exec_sql_fetchone(domain_id, dbname,
                                     "select * from sqlite_master where type='table' and name=?", name)
        return ret

    def find_transaction_locally(self, domain_id, transaction_id):
        """
        Find transaction data
        :param domain_id:
        :param transaction_id:
        :return:
        """
        row = self.exec_sql_fetchone(domain_id, "transaction_db",
                                     "select * from transaction_table where transaction_id = ?", transaction_id)
        if row is not None:
            return row[1]
        return None

    def find_by_sql_in_local_auxiliary_db(self, domain_id, sql, *dat):
        """
        find entries by SQL
        :param domain_id:
        :param sql:
        :param *dat:
        :return:
        """
        return self.exec_sql(domain_id, "auxiliary_db", sql, *dat)

    def insert_transaction_locally(self, domain_id, transaction_id, data):
        """
        Insert data in the local ledger

        :param domain_id:
        :param transaction_id:  Transaction_ID
        :param data:            Transaction Data (serialized)
        :param require_uniqueness: Ignore uniqueness if True
        :return: True/False
        """
        if self.exec_sql_fetchone(domain_id, "transaction_db",
                                  "select * from transaction_table where transaction_id = ?",
                                  transaction_id) is not None:
            return False
        self.exec_sql(domain_id, "transaction_db", "insert into transaction_table values (?, ?)", transaction_id, data)
        return True

    def insert_asset_info_locally(self, domain_id, transaction_id, asset_group_id, asset_id, user_id):
        """
        Insert data in the local ledger

        :param domain_id:
        :param transaction_id:
        :param asset_group_id:
        :param asset_id:
        :param user_id:
        :return: True/False
        """
        if self.exec_sql_fetchone(domain_id, "auxiliary_db",
                                  "select * from asset_info_table where transaction_id = ? AND asset_group_id = ? AND asset_id = ? AND user_id = ?",
                                  transaction_id, asset_group_id, asset_id, user_id) is not None:
            return False
        self.exec_sql(domain_id, "auxiliary_db", "insert into asset_info_table (transaction_id, asset_group_id, "
                                                 "asset_id, user_id) values (?, ?, ?, ?)",
                      transaction_id, asset_group_id, asset_id, user_id)
        return True

    def insert_topology_info_locally(self, domain_id, transaction_id, resource_type, resource_id):
        """
        Insert topology data for transactions
        :param domain_id:
        :param transaction_id:
        :param resource_type:
        :param resource_id:
        :return:
        """
        if self.exec_sql_fetchone(domain_id, "auxiliary_db",
                                  "select * from topology_table where transaction_id = ? AND resource_type = ? AND resource_id = ?",
                                  transaction_id, resource_type, resource_id) is not None:
            return False
        self.exec_sql(domain_id, "auxiliary_db", "insert into topology_table (transaction_id, resource_type, "
                                                 "resource_id) values (?, ?, ?)",
                      transaction_id, resource_type, resource_id)
        return True

    def remove(self, domain_id, transaction_id):
        """
        Remove all data with the specified transaction_id

        :param domain_id:
        :param transaction_id:  Transaction_ID
        :return: True/False
        """
        if self.exec_sql_fetchone(domain_id, "transaction_db",
                                  "select * from transaction_table where transaction_id = ?", transaction_id) is not None:
            self.exec_sql(domain_id, "transaction_db",
                          "delete from transaction_table where transaction_id = ?", transaction_id)
        if self.exec_sql_fetchone(domain_id, "auxiliary_db",
                                  "select * from asset_info_table where transaction_id = ?", transaction_id) is not None:
            self.exec_sql(domain_id, "auxiliary_db",
                          "delete from asset_info_table where transaction_id = ?", transaction_id)
        if self.exec_sql_fetchone(domain_id, "auxiliary_db",
                                  "select * from topology_table where transaction_id = ?", transaction_id) is not None:
            self.exec_sql(domain_id, "auxiliary_db",
                          "delete from topology_table where transaction_id = ?", transaction_id)
            self.exec_sql(domain_id, "auxiliary_db",
                          "delete from topology_table where resource_id = ?", transaction_id)
        return True
