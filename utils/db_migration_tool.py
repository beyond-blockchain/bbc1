#!/bin/sh
""":" .

exec python "$0" "$@"
"""
# -*- coding: utf-8 -*-
"""
Copyright (c) 2018 beyond-blockchain.org.

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
import argparse
from gevent import monkey
monkey.patch_all()
import os

import sys
sys.path.extend(["../../bbc1"])
from bbc1.core import bbc_config, data_handler, bbc_stats, logger


def parser():
    argparser = argparse.ArgumentParser(description='Database migration tool')
    argparser.add_argument('-c', '--config', type=str, default=None, help='config file name')
    argparser.add_argument('-w', '--workingdir', type=str, default=bbc_config.DEFAULT_WORKING_DIR, help='working directory', required=False)
    args = argparser.parse_args()
    return args


class NewDataHandler(data_handler.DataHandler):
    def __init__(self, domain_id_str=None, config=None, workingdir=None):
        self.logger = logger.get_logger("dummy")
        self.config = config
        self.working_dir = workingdir
        self.storage_root = os.path.join(self.working_dir, domain_id_str)
        if not os.path.exists(self.storage_root):
            os.makedirs(self.storage_root, exist_ok=True)
        self.stats = bbc_stats.BBcStats()  # dummy
        self.upgraded_from = data_handler.DB_VERSION
        self.db_adaptors = list()
        self.dbs = list()
        self._db_setup()


class MigrationTool:
    """Migration tool for """
    def __init__(self, workingdir=".bbc1", configfile=None):
        self.config = bbc_config.BBcConfig(workingdir, configfile, None).get_config()
        self.handlers = dict()
        for domain_id_str, conf in self.config['domains'].items():
            if 'db' not in conf:
                continue
            dh = NewDataHandler(domain_id_str=domain_id_str, config=conf, workingdir=workingdir)
            self.handlers[domain_id_str] = dh

    def upgrade(self):
        for domain_id_str, dh in self.handlers.items():
            print("*** Try to upgrade DB of domain_id = %s" % domain_id_str)
            for count in range(len(dh.db_adaptors)):
                print(" -- Upgrade from %s to %s" % (dh.upgraded_from, data_handler.DB_VERSION))
                print(" -- DB num:", count)
                ret = dh.exec_sql(db_num=count, sql="SELECT COUNT(*) FROM asset_info_table WHERE timestamp is NULL;")
                print("    Total target records:", ret[0][0])
                rows = dh.exec_sql(db_num=count, sql="SELECT * FROM asset_info_table WHERE timestamp is NULL;")
                total = 0
                for row in rows:
                    if row[5] is not None:  # skip if timestamp has been already set
                        continue
                    txid = row[1]
                    txrow = dh.search_transaction(transaction_id=txid, db_num=count)
                    if txrow[0] is None:
                        continue
                    txobj = txrow[0][txid]
                    dh.exec_sql(db_num=count,
                                sql="UPDATE asset_info_table SET timestamp = %s WHERE transaction_id = %s" %
                                    (dh.db_adaptors[count].placeholder, dh.db_adaptors[count].placeholder),
                                args=[txobj.timestamp, txid], commit=True)
                    total += 1
                    if total % 100 == 0:
                        print("    updated: %d records" % total)
                print("    [complete] updated: %d records" % total)


if __name__ == '__main__':
    argresult = parser()
    mt = MigrationTool(
        workingdir=argresult.workingdir,
        configfile=argresult.config,
    )
    mt.upgrade()
