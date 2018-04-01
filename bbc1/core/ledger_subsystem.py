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
import binascii
import copy
import hashlib
import json
import os
import threading

import sys
sys.path.extend(["../../"])
from bbc1.common import logger
from bbc1.core.ethereum import bbc_ethereum

temp_json = {
    "digest": None,
    "left": None,
    "right": None,
    "prev": None,
    "count": 0,
}


class Queue:
    def __init__(self):
        self.queue = []
        self.event = threading.Event()

    def wait_msg(self, flash_others=False):
        ret = None
        while ret is None:
            try:
                if len(self.queue) == 0:
                    self.event.wait()
                self.event.clear()
                ret = self.queue.pop(0)
            except:
                ret = None
        if flash_others:
            self.queue.clear()
            return ret
        return ret

    def append_msg(self, msg):
        self.queue.append(msg)
        self.event.set()


class LedgerSubsystem:
    """
    Abstraction of an underlying ledger subsystem that is typically a
    blockchain. This takes one transaction each to record and verifies its
    existence. It forms some Merkle trees of transaction IDs, and writes their
    root digests only to the underlying ledger.
    """
    def __init__(self, config, networking=None, domain_id=None, enabled=False, loglevel="all", logname=None):
        """
        Constructs a ledger subsystem. Just supports sqlite3.

        :param config: configuration object
        :param networking: networking (need access to ledger manager)
        :param domain_id:
        :param enabled: if communication with the underlying ledger is enabled
        :param loglevel: loggging level
        :param logname: name of log
        :return:
        """
        self.networking = networking
        self.domain_id = domain_id
        if domain_id is None:
            return
        self.data_handler = self.networking.domains[domain_id]['data']
        self.logger = logger.get_logger(key="ledger_subsystem", level=loglevel, logname=logname)
        self.queue = Queue()
        self.enabled = enabled
        self.config = config.get_domain_config(self.domain_id)
        conf = config.get_config()
        self.eth_config = None if "ethereum" not in conf else conf["ethereum"]
        self.eth = None
        self.capacity = self.config['ledger_subsystem']['max_transactions']
        self.interval = self.config['ledger_subsystem']['max_seconds']
        self.timer = None
        self.temp_file_dic = os.path.join(self.data_handler.storage_root, 'ledger_subsystem.json')

        if self.enabled:
            self.enable()
        thread_loop = threading.Thread(target=self.subsystem_loop)
        thread_loop.setDaemon(True)
        thread_loop.start()

    def append_msg(self, msg):
        self.queue.append_msg(msg=msg)

    def close_merkle_tree(self, jTemp):
        self.logger.debug("closing a merkle tree")
        self.timer.cancel()
        self.timer = threading.Timer(self.interval, self.subsystem_timer)
        self.timer.start()
        digest = None
        if jTemp['left'] is not None:
            jTemp['right'] == jTemp['left']
            msg = binascii.a2b_hex(jTemp['left'])
            digest = hashlib.sha256(msg + msg).digest()
            jTemp['digest'] = str(binascii.b2a_hex(digest), 'utf-8')
            self.write_leaf(jTemp, digest=digest, left=msg, right=msg)
        elif jTemp['prev'] is not None:
            digest = binascii.a2b_hex(jTemp['prev'])
        f = open(self.temp_file_dic, 'w')
        json.dump(temp_json, f, indent=2)
        f.close()
        if digest is None:
            self.logger.debug("nothing to close")
            return
        lBase = self.get_merkle_base(digest)
        while True:
            count = 0
            dLeft = None
            lTop = list()
            for digest in lBase:
                if dLeft is None:
                    dLeft = digest
                else:
                    dRight = digest
                    digest = hashlib.sha256(dLeft + dRight).digest()
                    self.write_branch(digest=digest, left=dLeft, right=dRight)
                    lTop.append(digest)
                    dLeft = None
                count += 1
            if dLeft is not None:
                dRight = dLeft
                digest = hashlib.sha256(dLeft + dRight).digest()
                self.write_branch(digest=digest, left=dLeft, right=dRight)
                lTop.append(digest)
            lBase = lTop
            if count <= 2:
                break
        if self.config['ledger_subsystem']['subsystem'] == 'ethereum':
            self.write_merkle_root(lBase[0])

    def enable(self):
        """
        Enables communication with the underlying ledger.

        :return:
        """
        if self.config['ledger_subsystem']['subsystem'] == 'ethereum':
            prevdir = os.getcwd()
            os.chdir('ethereum')
            self.eth = bbc_ethereum.BBcEthereum(
                self.config['ethereum']['account'],
                self.config['ethereum']['passphrase'],
                self.config['ethereum']['contract_address']
            )
            os.chdir(prevdir)
        else:
            self.logger.error("Currently, Ethereum only is supported.")
            os.exit(1)
        self.timer = threading.Timer(self.interval, self.subsystem_timer)
        self.timer.start()
        self.enabled = True

    def disable(self):
        """
        Disables communication with the underlying ledger.

        :return:
        """
        self.timer.cancel()
        self.enabled = False

    def get_merkle_base(self, digest):
        lBase = list()
        while True:
            row = self.data_handler.exec_sql(
                sql="select * from merkle_leaf_table where digest=%s" % self.data_handler.db_adaptors[0].placeholder,
                args=(digest,)
            )
            if row is None:
                break
            lBase.insert(0, row[0][0])
            digest = row[0][3]
        return lBase

    def register_transaction(self, transaction_id):
        """
        Registers a transaction.

        :param transaction_id: transaction to register
        :return:
        """
        if self.enabled:
            self.append_msg(transaction_id)
        else:
            self.logger.warning("ledger subsystem not enabled")

    def subsystem_loop(self):
        self.logger.debug("Start subsystem_loop for domain:%s" % self.domain_id.hex())
        self.domain_id = None
        while True:
            msg = self.queue.wait_msg()
            if os.path.exists(self.temp_file_dic):
                f = open(self.temp_file_dic, 'r')
                jTemp = json.load(f)
                f.close()
            else:
                jTemp = copy.deepcopy(temp_json)
            if type(msg) == tuple:
                if msg[0] == 'timer':
                    self.logger.debug("got message: %s" % msg[0])
                    self.close_merkle_tree(jTemp)
                elif msg[0] == 'verify':
                    self.logger.debug("got message: %s %s" % (msg[0], msg[1]))
                    self.verify_digest(msg[1], msg[3])
                    msg[2].set()
            else:
                self.logger.debug("got message: %s" % msg)
                digest = None
                if jTemp['left'] is None:
                    jTemp['left'] = str(binascii.b2a_hex(msg), 'utf-8')
                elif jTemp['right'] is None:
                    jTemp['right'] = str(binascii.b2a_hex(msg), 'utf-8')
                    target = binascii.a2b_hex(jTemp['left']) + msg
                    digest = hashlib.sha256(target).digest()
                    jTemp['digest'] = str(binascii.b2a_hex(digest), 'utf-8')
                f = open(self.temp_file_dic, 'w')
                json.dump(jTemp, f, indent=2)
                f.close()
                if jTemp['digest'] is not None:
                    self.write_leaf(jTemp, digest=digest, right=msg)
                if jTemp['count'] >= self.capacity:
                    self.close_merkle_tree(jTemp)

    def subsystem_timer(self):
        self.append_msg(('timer',))

    def verify_transaction(self, transaction_id):
        """
        Verifies whether the specified transaction is registered or not.

        :param transaction_id: transaction to verify its existence
        :return: dictionary containing the result (and a Merkle subtree)
        """
        dic = dict()
        if self.enabled:
            e = threading.Event()
            self.append_msg(('verify', transaction_id, e, dic))
            e.wait()
        else:
            self.logger.warning("ledger subsystem not enabled")
        return dic

    def verify_digest(self, digest, dic):
        row = self.data_handler.exec_sql(
            sql="select * from merkle_leaf_table where leaf_left=%s or leaf_right=%s" %
                (self.data_handler.db_adaptors[0].placeholder, self.data_handler.db_adaptors[0].placeholder),
            args=(digest,digest)
        )
        if row is None:
            self.logger.debug("transaction not found")
            dic['result'] = False
            return
        subtree = list()
        while True:
            subtree.append({
                'position': 'left' if row[0][2] == digest else 'right',
                'digest': str(binascii.b2a_hex(
                    row[1] if row[2] == digest else row[0][2]
                ), 'utf-8')
            })
            digest = row[0][0]
            row = self.data_handler.exec_sql(
                sql="select * from merkle_branch_table where leaf_left=%s or leaf_right=%s" %
                    (self.data_handler.db_adaptors[0].placeholder, self.data_handler.db_adaptors[0].placeholder),
                args=(digest,digest)
            )
            if row is None:
                break
        row = self.data_handler.exec_sql(
            sql="select * from merkle_root_table where root=%s" % self.data_handler.db_adaptors[0].placeholder,
            args=(digest,)
        )
        if row is None:
            self.logger.warning("merkle root not found")
            dic['result'] = False
            return
        specList = row[1].split(':')
        block = self.eth.test(digest)
        if block <= 0:
            self.logger.warning("merkle root not anchored")
            dic['result'] = False
            return
        spec = {
            'subsystem': specList[0],
            'chain_id': specList[1],
            'contract': specList[2],
            'contract_address': specList[3],
            'block': block,
        }
        dic['result'] = True
        dic['spec'] = spec
        dic['subtree'] = subtree

    def write_branch(self, digest=None, left=None, right=None):
        row = self.data_handler.exec_sql(
            sql="select * from merkle_branch_table where digest=%s" % self.data_handler.db_adaptors[0].placeholder,
            args=(digest,)
        )
        if row is not None:
            self.logger.warning("collision of digests detected")
        else:
            self.data_handler.exec_sql(
                sql="insert into merkle_branch_table values (%s, %s, %s)" %
                    (self.data_handler.db_adaptors[0].placeholder,
                     self.data_handler.db_adaptors[0].placeholder,
                     self.data_handler.db_adaptors[0].placeholder),
                args=(digest, left, right),
                commit=True
            )

    def write_leaf(self, jTemp, digest=None, left=None, right=None):
        if digest is None:
            digest = binascii.a2b_hex(jTemp['digest'])
        if jTemp['prev'] is None:
            prev = bytes()
        else:
            prev = binascii.a2b_hex(jTemp['prev'])
        row = self.data_handler.exec_sql(
            sql="select * from merkle_leaf_table where digest=%s" % self.data_handler.db_adaptors[0].placeholder,
            args=(digest,)
        )
        if row is not None:
            self.logger.warning("collision of digests detected")
        else:
            self.data_handler.exec_sql(
                sql="insert into merkle_leaf_table values (%s, %s, %s, %s)" %
                    (self.data_handler.db_adaptors[0].placeholder, self.data_handler.db_adaptors[0].placeholder,
                     self.data_handler.db_adaptors[0].placeholder,self.data_handler.db_adaptors[0].placeholder),
                args=(digest,
                      left if left is not None else binascii.a2b_hex(jTemp['left']),
                      right if right is not None else binascii.a2b_hex(jTemp['right']),
                      prev),
                commit=True
            )
        jTemp['prev'] = jTemp['digest']
        jTemp['digest'] = None
        jTemp['left'] = None
        jTemp['right'] = None
        jTemp['count'] += 2
        f = open(self.temp_file_dic, 'w')
        json.dump(jTemp, f, indent=2)
        f.close()

    def write_merkle_root(self, root):
        self.write_root(
            root=root,
            spec='ethereum:%d:BBcAnchor:%s' %
                 (self.eth_config['chain_id'],
                  self.eth_config['contract_address'])
        )
        self.eth.blockingSet(root)

    def write_root(self, root=None, spec=None):
        root = self.data_handler.exec_sql(
            sql="select * from merkle_root_table where root=%s" % self.data_handler.db_adaptors[0].placeholder,
            args=(root,)
        )
        if root is not None:
            self.logger.warning("collision of digests detected")
        else:
            self.data_handler.exec_sql(
                sql="insert into merkle_root_table values (%s, %s)" %
                    (self.data_handler.db_adaptors[0].placeholder, self.data_handler.db_adaptors[0].placeholder),
                args=(root, spec),
                commit=True
            )

# end of core/ledger_subsystem.py
