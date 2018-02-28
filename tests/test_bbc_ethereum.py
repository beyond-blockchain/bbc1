# -*- coding: utf-8 -*-
import pytest
import json
import os
import subprocess
import time

import sys
sys.path.extend(["../"])
from bbc1.core import bbc_config
from bbc1.core.ethereum import setup
from bbc1.core.ethereum import bbc_ethereum


TEST_CONFIG_FILE = 'test_config.json'
TEST_LOG_FILE = 'test_geth.log'
TEST_PASSPHRASE1 = 'foo'
TEST_PASSPHRASE2 = 'bar'


class Args:

    def __init__(self):

        self.workingdir = bbc_config.DEFAULT_WORKING_DIR
        self.config = TEST_CONFIG_FILE
        self.networkid = bbc_config.DEFAULT_ETHEREUM_CHAIN_ID
        self.port = bbc_config.DEFAULT_ETHEREUM_GETH_PORT
        self.log = TEST_LOG_FILE


@pytest.fixture()
def default_config():
    return setup.setup_config(Args())


def test_setup_populus():

    setup.setup_populus()

    prevdir = os.getcwd()
    dir = os.path.dirname(os.path.realpath(__file__))
    os.chdir(dir)
    os.chdir('../bbc1/core/ethereum')

    if os.path.exists('populus.json'):
        f = open('populus.json', 'r')
    else:
        f = open('project.json', 'r')
    jPop = json.load(f)
    f.close()

    jBBcChain = jPop['chains']['bbc']

    assert jBBcChain['chain']['class'] == 'populus.chain.ExternalChain'

    os.chdir(prevdir)
    print("\n==> populus is set up.")


def test_setup_genesis(default_config):

    setup.setup_genesis(default_config)

    prevdir = os.getcwd()
    dir = os.path.dirname(os.path.realpath(__file__))
    os.chdir(dir)
    os.chdir('../bbc1/core/ethereum')

    f = open('genesis.json', 'r')
    jGenesis = json.load(f)
    f.close()

    assert jGenesis['config']['chainId'] == default_config.get_config()['ethereum']['chain_id']
    assert jGenesis['config']['homesteadBlock'] == 0
    assert jGenesis['config']['eip155Block'] == 0
    assert jGenesis['config']['eip158Block'] == 0
    assert jGenesis['difficulty'] == '0x200'
    assert jGenesis['gasLimit'] == '2100000'

    os.chdir(prevdir)
    print("\n==> genesis block is set up.")


def test_setup_new_account(default_config):

    setup.setup_new_account(default_config, TEST_PASSPHRASE1)

    prevdir = os.getcwd()
    dir = os.path.dirname(os.path.realpath(__file__))
    os.chdir(dir)
    os.chdir('../bbc1/core/' + bbc_config.DEFAULT_WORKING_DIR)

    f = open(TEST_CONFIG_FILE, 'r')
    config = json.load(f)
    f.close()

    account = config['ethereum']['account']

    assert account[0:2] == '0x'
    assert len(account) == 42

    assert config['ethereum']['passphrase'] == TEST_PASSPHRASE1

    os.chdir(prevdir)
    print("\n==> new account is set.")


def test_setup_account(default_config):

    prevdir = os.getcwd()
    dir = os.path.dirname(os.path.realpath(__file__))
    os.chdir(dir)
    os.chdir('../bbc1/core/' + bbc_config.DEFAULT_WORKING_DIR)

    f = open(TEST_CONFIG_FILE, 'r')
    config = json.load(f)
    f.close()

    os.chdir(prevdir)

    account = config['ethereum']['account']
    passphrase = config['ethereum']['passphrase']

    setup.setup_new_account(default_config, TEST_PASSPHRASE2)
    setup.setup_account(default_config, account, passphrase)

    os.chdir(dir)
    os.chdir('../bbc1/core/' + bbc_config.DEFAULT_WORKING_DIR)

    f = open(TEST_CONFIG_FILE, 'r')
    config = json.load(f)
    f.close()

    assert config['ethereum']['account'] == account
    assert config['ethereum']['passphrase'] == passphrase

    os.chdir(prevdir)
    print("\n==> another account is set.")


def test_setup_run(default_config):

    setup.setup_run(default_config)

    prevdir = os.getcwd()
    dir = os.path.dirname(os.path.realpath(__file__))
    os.chdir(dir)
    os.chdir('../bbc1/core/' + bbc_config.DEFAULT_WORKING_DIR)

    f = open(TEST_CONFIG_FILE, 'r')
    config = json.load(f)
    f.close()

    pid = config['ethereum']['pid']

    bytes = subprocess.check_output(['ps', '-p', str(pid)])
    s = bytes.decode('utf-8')
    assert s.find(str(pid)) >= 0
    assert s.find('geth') >= 0

    time.sleep(5)

    os.chdir(prevdir)
    print("\n==> geth is running.")


def test_setup_deploy(default_config):

    setup.setup_deploy(default_config)

    prevdir = os.getcwd()
    dir = os.path.dirname(os.path.realpath(__file__))
    os.chdir(dir)
    os.chdir('../bbc1/core/' + bbc_config.DEFAULT_WORKING_DIR)

    f = open(TEST_CONFIG_FILE, 'r')
    config = json.load(f)
    f.close()

    address = config['ethereum']['contract_address']

    assert address[0:2] == '0x'
    assert len(address) == 42

    os.chdir('../ethereum')

    eth = bbc_ethereum.BBcEthereum(config['ethereum']['account'],
                                   config['ethereum']['passphrase'],
                                   address)

    eth.blockingSet(0x1234)

    assert eth.test(0x1230) == 0
    assert eth.test(0x1234) > 0

    eth.blockingSet(b'\x43\x21')

    assert eth.test(0x4321) > 0
    assert eth.test(b'\x43\x21') > 0

    os.chdir(prevdir)
    print("\n==> BBcAnchor is deployed and tested.")


def test_setup_stop(default_config):

    prevdir = os.getcwd()
    dir = os.path.dirname(os.path.realpath(__file__))
    os.chdir(dir)
    os.chdir('../bbc1/core/' + bbc_config.DEFAULT_WORKING_DIR)

    f = open(TEST_CONFIG_FILE, 'r')
    config = json.load(f)
    f.close()

    os.chdir(prevdir)

    pid = config['ethereum']['pid']

    setup.setup_stop(default_config)

    os.chdir(dir)
    os.chdir('../bbc1/core/' + bbc_config.DEFAULT_WORKING_DIR)

    f = open(TEST_CONFIG_FILE, 'r')
    config = json.load(f)
    f.close()

    assert config['ethereum']['pid'] == None

    time.sleep(2)
    flag = False

    try:
        bytes = subprocess.check_output(['ps', '-p', str(pid)])
    except subprocess.CalledProcessError as e:
        flag = True

    assert flag == True

    os.chdir(prevdir)
    print("\n==> geth is stopped.")


# end of tests/test_bbc_ethereum_.py
