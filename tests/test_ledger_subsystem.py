# -*- coding: utf-8 -*-
"""
Run tests/test_bbc_ethereum.py before this to fill an account data and deploy
a contract for testing.
After the test is complete, the program needs to be stopped by a keyboard
interrupt.
"""
import pytest
import hashlib
import json
import os
import subprocess
import time

import sys
sys.path.append('.')
sys.path.append('..')
from bbc1.common import bbclib
from bbc1.core import bbc_config
from bbc1.core import bbc_ledger
from bbc1.core import ledger_subsystem
from bbc1.core.ethereum import setup
from bbc1.core.ethereum import bbc_ethereum
from tests import test_bbc_ethereum


class DummyCore:

    def __init__(self, config):
        self.ledger_manager = bbc_ledger.BBcLedger(config)


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
    eth = bbc_ethereum.BBcEthereum(
        conf['ethereum']['account'],
        conf['ethereum']['passphrase'],
        conf['ethereum']['contract_address']
    )

    os.chdir('..')

    dummycore = DummyCore(default_config)
    domain_id = bbclib.get_new_id("test_domain")
    asset_group_id = bbclib.get_new_id("asset_group_1")

    dummycore.ledger_manager.add_domain(domain_id)
    ls = ledger_subsystem.LedgerSubsystem(default_config,
                                          core=dummycore, enabled=True)
    ls.set_domain(domain_id)

    for i in range(150):
        ls.register_transaction(asset_group_id,
                                hashlib.sha256(i.to_bytes(4, 'big')).digest())
        time.sleep(0.1)

    time.sleep(30)

    i = 300
    j = ls.verify_transaction(asset_group_id,
                              hashlib.sha256(i.to_bytes(4, 'big')).digest())

    assert j['result'] == False

    for i in range(150):
        digest = hashlib.sha256(i.to_bytes(4, 'big')).digest()
        j = ls.verify_transaction(asset_group_id, digest)
        assert j['result'] == True
        assert eth.verify(digest, j['subtree']) > 0

    domain_id = bbclib.get_new_id("test_domain_a")
    dummycore.ledger_manager.add_domain(domain_id)
    ls.set_domain(domain_id)

    i = 100
    j = ls.verify_transaction(asset_group_id,
                              hashlib.sha256(i.to_bytes(4, 'big')).digest())

    assert j['result'] == False

    i = 99
    digest = hashlib.sha256(i.to_bytes(4, 'big')).digest()
    ls.register_transaction(asset_group_id, digest)

    time.sleep(31)

    j = ls.verify_transaction(asset_group_id, digest)
    assert j['result'] == True
    assert eth.verify(digest, j['subtree']) > 0

    os.chdir(prevdir)

    setup.setup_stop(default_config)


# end of tests/test_ledger_subsystem_.py
