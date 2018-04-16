# -*- coding: utf-8 -*-
"""
Run tests/test_bbc_ethereum.py before this to fill an account data and deploy
a contract for testing.
After the test is complete, the program may need to be stopped by a keyboard
interrupt.
"""
import pytest
import hashlib
import os
import time

import sys
sys.path.append('.')
sys.path.append('..')
from bbc1.common import bbclib
from bbc1.core import ledger_subsystem, bbc_stats, bbc_network, bbc_config
from bbc1.core.ethereum import setup
from bbc1.core.ethereum import bbc_ethereum
from tests import test_bbc_ethereum


DEFAULT_ETHEREUM_LOG_FILE = 'geth.log'
DEFAULT_ETHEREUM_CHAIN_ID = 15
DEFAULT_ETHEREUM_GETH_PORT = 30303

domain_id1 = bbclib.get_new_id("test_domain1")
domain_id2 = bbclib.get_new_id("test_domain2")


class DummyCore:
    class UserMessageRouting:
        def add_domain(self, domain_id):
            pass

        def remove_domain(self, domain_id):
            pass

    def __init__(self):
        self.user_message_routing = DummyCore.UserMessageRouting()
        self.stats = bbc_stats.BBcStats()


@pytest.fixture()
def default_config():

    config = setup.setup_config(test_bbc_ethereum.Args())
    conf = config.get_config()

    db_conf = {
        "db_type": "sqlite",
        "db_name": "bbc_ledger.sqlite",
        "replication_strategy": "all",
        "db_servers": [
            {
                "db_addr": "127.0.0.1",
                "db_port": 3306,
                "db_user": "user",
                "db_pass": "pass"
            }
        ]
    }

    domain_id1_conf = {
        'storage': {
            'type': 'internal',
        },
        'db': db_conf,
        'use_ledger_subsystem': True,
        'ledger_subsystem': {
            'subsystem': 'ethereum',
            'max_transactions': 100,
            'max_seconds': 30,
        },
    }
    domain_id2_conf = {
        'storage': {
            'type': 'internal',
        },
        'db': db_conf,
        'use_ledger_subsystem': True,
        'ledger_subsystem': {
            'subsystem': 'ethereum',
            'max_transactions': 100,
            'max_seconds': 30,
        },
    }

    conf['domains'][domain_id1.hex()] = domain_id1_conf
    conf['domains'][domain_id2.hex()] = domain_id2_conf

    return config


def test_ledger_subsystem(default_config):

    setup.setup_run(default_config)

    prevdir = os.getcwd()
    dir = os.path.dirname(os.path.realpath(__file__))
    os.chdir(dir)
    os.chdir('../bbc1/core/ethereum')

    conf = default_config.get_config()
    print(conf)
    eth = bbc_ethereum.BBcEthereum(
        conf['ethereum']['account'],
        conf['ethereum']['passphrase'],
        conf['ethereum']['contract_address']
    )

    os.chdir('..')

    networking = bbc_network.BBcNetwork(core=DummyCore(),
            config=default_config, p2p_port=6641)
    networking.create_domain(domain_id=domain_id1)

    ls = ledger_subsystem.LedgerSubsystem(default_config,
            networking=networking, domain_id=domain_id1, enabled=True)

    for i in range(150):
        ls.register_transaction(hashlib.sha256(i.to_bytes(4, 'big')).digest())

    print("\n30-second interval for trigger Merkle tree creation.")
    for i in range(6, 0, -1):
        print("continuing to sleep. countdown", i)
        time.sleep(5)

    i = 300
    j = ls.verify_transaction(hashlib.sha256(i.to_bytes(4, 'big')).digest())

    assert not j['result']

    for i in range(150):
        digest = hashlib.sha256(i.to_bytes(4, 'big')).digest()
        j = ls.verify_transaction(digest)
        assert j['result']
        assert eth.verify(digest, j['subtree']) > 0

    # -- test in another domain
    networking.create_domain(domain_id=domain_id2)
    ls = ledger_subsystem.LedgerSubsystem(default_config,
            networking=networking, domain_id=domain_id2, enabled=True)

    i = 100
    j = ls.verify_transaction(hashlib.sha256(i.to_bytes(4, 'big')).digest())

    assert not j['result']

    i = 99
    digest = hashlib.sha256(i.to_bytes(4, 'big')).digest()
    ls.register_transaction(digest)

    print("31-second interval for trigger Merkle tree creation.")
    time.sleep(1)
    for i in range(6, 0, -1):
        print("continuing to sleep. countdown", i)
        time.sleep(5)

    j = ls.verify_transaction(digest)
    assert j['result']
    assert eth.verify(digest, j['subtree']) > 0

    os.chdir(prevdir)
    setup.setup_stop(default_config)


# end of tests/test_ledger_subsystem_.py
