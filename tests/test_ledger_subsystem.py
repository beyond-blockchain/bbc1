# -*- coding: utf-8 -*-
"""
Run tests/test_bbc_ethereum.py before this to fill an account data and deploy
a contract for testing.
After the test is complete, the program needs to be stopped by a keyboard
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

default_config = {
    'domains': {
        domain_id1.hex(): {
            'use_ledger_subsystem': True,  # if this items does not exist or False, ledger_subsystem will not be used
            'ledger_subsystem': {
                'subsystem': 'ethereum',
                'max_transactions': 4096,
                'max_seconds': 60 * 60,
            },
        },
        domain_id2.hex(): {
            'use_ledger_subsystem': True,  # if this items does not exist or False, ledger_subsystem will not be used
            'ledger_subsystem': {
                'subsystem': 'ethereum',
                'max_transactions': 4096,
                'max_seconds': 60 * 60,
            },
        },
    },
    'ethereum': {
        'chain_id': DEFAULT_ETHEREUM_CHAIN_ID,
        'port': DEFAULT_ETHEREUM_GETH_PORT,
        'log': DEFAULT_ETHEREUM_LOG_FILE,
        'account': '',
        'passphrase': '',
        'contract': 'BBcAnchor',
        'contract_address': '',
    },
}

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
    conf['ledger_subsystem'] = {
        'subsystem': 'ethereum',
        'max_transactions': 100,
        'max_seconds': 30,
    }

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

    networking = bbc_network.BBcNetwork(core=DummyCore(), config=conf, p2p_port=6641)
    networking.create_domain(domain_id=domain_id1)

    ls = ledger_subsystem.LedgerSubsystem(conf, networking=networking, domain_id=domain_id1, enabled=True)

    for i in range(150):
        ls.register_transaction(hashlib.sha256(i.to_bytes(4, 'big')).digest())

        time.sleep(0.1)

    time.sleep(30)

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
    ls = ledger_subsystem.LedgerSubsystem(conf, networking=networking, domain_id=domain_id2, enabled=True)

    i = 100
    j = ls.verify_transaction(hashlib.sha256(i.to_bytes(4, 'big')).digest())

    assert not j['result']

    i = 99
    digest = hashlib.sha256(i.to_bytes(4, 'big')).digest()
    ls.register_transaction(digest)

    time.sleep(31)

    j = ls.verify_transaction(digest)
    assert j['result']
    assert eth.verify(digest, j['subtree']) > 0

    setup.setup_stop(default_config)


# end of tests/test_ledger_subsystem_.py
