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
import argparse
import json
import os
import subprocess

import sys
sys.path.append('../../..')
from bbc1.core import bbc_config
from bbc1.core.ethereum import bbc_ethereum


def argument_parser():

    argparser = argparse.ArgumentParser()

    argparser.add_argument('-c', '--config', type=str,
                           default=bbc_config.DEFAULT_CONFIG_FILE,
                           help='config file name')
    argparser.add_argument('-l', '--log', type=str,
                           default=bbc_config.DEFAULT_ETHEREUM_LOG_FILE,
                           help='geth log file name')
    argparser.add_argument('-n', '--networkid', type=int,
                           default=bbc_config.DEFAULT_ETHEREUM_CHAIN_ID,
                           help='geth networkd id number')
    argparser.add_argument('-p', '--port', type=int,
                           default=bbc_config.DEFAULT_ETHEREUM_GETH_PORT,
                           help='geth port number')
    argparser.add_argument('-w', '--workingdir', type=str,
                           default=bbc_config.DEFAULT_WORKING_DIR,
                           help='working directory name (relative to core)')

    subparsers = argparser.add_subparsers(dest='command_type',
                                          help='select commands')

    # account command
    account_parser = subparsers.add_parser('account',
                                           help='Set an Ethereum account')
    account_parser.add_argument('address', action='store',
                                help='Address of the account')
    account_parser.add_argument('passphrase', action='store',
                                help='Passphrase of the account')

    # auto command
    account_parser = subparsers.add_parser('auto',
                                        help='Automatically set up everything')
    account_parser.add_argument('passphrase', action='store',
                                help='Passphrase of a new account')

    # deploy command
    subparsers.add_parser('deploy', help='Deploy the anchor contract')

    # genesis command
    subparsers.add_parser('genesis', help='Create Ethereum genesis block')

    # new_account command
    account_parser = subparsers.add_parser('new_account',
                                        help='Create a new Ethereum account')
    account_parser.add_argument('passphrase', action='store',
                                help='Passphrase of the new account')

    # populus command
    subparsers.add_parser('populus', help='Initialize populus environment')

    # run command
    subparsers.add_parser('run', help='Run local geth node')

    # stop command
    subparsers.add_parser('stop', help='Stop local geth node')

    # test command
    subparsers.add_parser('test', help='Test the anchor contract')

    return argparser.parse_args()


def setup_account(bbcConfig, account, passphrase):
    """
    Sets the specified Ethereum account to be used in the ledger subsystem.

    :param bbcConfig: configuration object
    :param account: Ethereum account in hexadecimal prefixed with '0x'
    :param passphrase: Passphrase to unlock the account
    :return:
    """
    prevdir = os.getcwd()
    dirpath = os.path.dirname(os.path.realpath(__file__))
    os.chdir(dirpath)
    os.chdir('..')

    config = bbcConfig.get_config()
    config['ethereum']['account'] = account
    config['ethereum']['passphrase'] = passphrase
    bbcConfig.update_config()

    os.chdir(prevdir)


def setup_config(args):

    prevdir = os.getcwd()
    dirpath = os.path.dirname(os.path.realpath(__file__))
    os.chdir(dirpath)
    os.chdir('..')

    bbcConfig = bbc_config.BBcConfig(args.workingdir, args.config)
    config = bbcConfig.get_config()

    isUpdated = False

    if not 'ethereum' in config:
        config['ethereum'] = {
            'chain_id': args.networkid,
            'port': args.port,
            'log': args.log,
            'account': '',
            'passphrase': '',
            'contract_address': '',
        }
        isUpdated = True

    elif config['ethereum']['chain_id'] != args.networkid:
        config['ethereum']['chain_id'] = args.networkid
        isUpdated = True

    elif config['ethereum']['port'] != args.port:
        config['ethereum']['port'] = args.port
        isUpdated = True

    elif config['ethereum']['log'] != args.log:
        config['ethereum']['log'] = args.log
        isUpdated = True

    if isUpdated:
        bbcConfig.update_config()

    os.chdir(prevdir)

    return bbcConfig


def setup_deploy(bbcConfig):
    """
    Deploys BBcAnchor contract to Ethereum ledger subsystem.

    :param bbcConfig: configuration object
    :return:
    """
    prevdir = os.getcwd()
    dirpath = os.path.dirname(os.path.realpath(__file__))
    os.chdir(dirpath)

    config = bbcConfig.get_config()
    bbcEthereum = bbc_ethereum.BBcEthereum(config['ethereum']['account'],
                                             config['ethereum']['passphrase'])

    contract_address = config['ethereum']['contract_address']
    if contract_address != '':
        config['ethereum']['previous_contract_address'] = contract_address

    config['ethereum']['contract_address'] = bbcEthereum.get_contract_address()
    os.chdir('..')
    bbcConfig.update_config()

    os.chdir(prevdir)


def setup_genesis(bbcConfig):
    """
    Creates the genesis block of Ethereum ledger subsystem.

    :param bbcConfig: configuration object
    :return:
    """
    prevdir = os.getcwd()
    dirpath = os.path.dirname(os.path.realpath(__file__))
    os.chdir(dirpath)

    config = bbcConfig.get_config()

    jGenesis = {
      "config": {
        "chainId": config['ethereum']['chain_id'],
        "homesteadBlock": 0,
        "eip155Block": 0,
        "eip158Block": 0
      },
      "difficulty": "0x200",
      "gasLimit": "2100000",
      "alloc": {
      }
    }

    f = open('genesis.json', 'w')
    json.dump(jGenesis, f, indent=2)
    f.close()

    subprocess.call(['geth', 'init', 'genesis.json'])

    os.chdir(prevdir)


def setup_new_account(bbcConfig, passphrase):
    """
    Creates a new Ethereum account to be used in the ledger subsystem.

    :param bbcConfig: configuration object
    :param passphrase: Passphrase to unlock the new account
    :return:
    """
    PASSWORD_FILE = '_password'

    prevdir = os.getcwd()
    dirpath = os.path.dirname(os.path.realpath(__file__))
    os.chdir(dirpath)
    os.chdir('..')

    f = open(PASSWORD_FILE, 'w')
    f.write(passphrase + '\n')
    f.close()

    bytes = subprocess.check_output(
        ['geth', 'account', 'new', '--password', PASSWORD_FILE]
    )

    config = bbcConfig.get_config()
    config['ethereum']['account'] = '0x' + bytes.decode('utf-8')[10:50]
    config['ethereum']['passphrase'] = passphrase
    bbcConfig.update_config()

    os.remove(PASSWORD_FILE)

    os.chdir(prevdir)


def setup_populus():
    """
    Sets up a Populus environment to communicate with Ethereum ledger subsytem.
    Initializes the environment and compiles BBcAnchor contract.

    :return:
    """
    prevdir = os.getcwd()
    dirpath = os.path.dirname(os.path.realpath(__file__))
    os.chdir(dirpath)

    subprocess.call(['populus', 'init'])

    os.remove('contracts/Greeter.sol')
    os.remove('tests/test_greeter.py')

    if os.path.exists('populus.json'):

        f = open('populus.json', 'r')
        jPop = json.load(f)
        f.close()

        jBBcChain = {
          "chain": {
            "class": "populus.chain.ExternalChain"
          },
          "contracts": {
            "backends": {
              "JSONFile": {
                "$ref": "contracts.backends.JSONFile"
              },
              "Memory": {
                "$ref": "contracts.backends.Memory"
              },
              "ProjectContracts": {
                "$ref": "contracts.backends.ProjectContracts"
              },
              "TestContracts": {
                "$ref": "contracts.backends.TestContracts"
              }
            }
          },
          "web3": {
            "$ref": "web3.GethIPC"
          }
        }
    
        jChains = jPop['chains']
        jChains['bbc'] = jBBcChain

        f = open('populus.json', 'w')
        json.dump(jPop, f, indent=2)
        f.close()

    elif os.path.exists('project.json'):

        f = open('project.json', 'r')
        jPop = json.load(f)
        f.close()

        jBBcChain = {
          "chain": {
            "class": "populus.chain.ExternalChain"
          },
          "contracts": {
            "backends": {
              "JSONFile": {
                "class": "populus.contracts.backends.filesystem.JSONFileBackend",
                "priority": 10,
                "settings": {
                  "file_path": "./registrar.json"
                }
              },
              "Memory": {
                "class": "populus.contracts.backends.memory.MemoryBackend",
                "priority": 50
              },
              "ProjectContracts": {
                "class": "populus.contracts.backends.project.ProjectContractsBackend",
                "priority": 20
              },
              "TestContracts": {
                "class": "populus.contracts.backends.testing.TestContractsBackend",
                "priority": 40
              }
            }
          },
          "web3": {
            "provider": {
              "class": "web3.providers.ipc.IPCProvider"
            }
          }
        }
    
        jChains = dict()
        jChains['bbc'] = jBBcChain
        jPop['chains'] = jChains

        f = open('project.json', 'w')
        json.dump(jPop, f, indent=2)
        f.close()

    subprocess.call(['populus', 'compile'])

    os.chdir(prevdir)


def setup_run(bbcConfig):
    """
    Runs a geth Ethereum node.

    :param bbcConfig: configuration object
    :return:
    """
    prevdir = os.getcwd()
    dirpath = os.path.dirname(os.path.realpath(__file__))
    os.chdir(dirpath)

    config = bbcConfig.get_config()

    log = open(config['ethereum']['log'], 'a')

    proc = subprocess.Popen([
        'geth',
        '--networkid', str(config['ethereum']['chain_id']),
        '--port', str(config['ethereum']['port']),
        '--maxpeers', '0',
        '--nodiscover',
        '--etherbase', config['ethereum']['account'],
        '--mine',
    ], stderr=log)

    config['ethereum']['pid'] = proc.pid
    os.chdir('..')
    bbcConfig.update_config()

    os.chdir(prevdir)


def setup_stop(bbcConfig):
    """
    Stops a geth Ethereum node.

    :param bbcConfig: configuration object
    :return:
    """
    prevdir = os.getcwd()
    dirpath = os.path.dirname(os.path.realpath(__file__))
    os.chdir(dirpath)
    os.chdir('..')

    config = bbcConfig.get_config()

    subprocess.call(['kill', str(config['ethereum']['pid'])])

    config['ethereum']['pid'] = None
    bbcConfig.update_config()

    os.chdir(prevdir)


def setup_test():
    """
    Tests BBcAnchor contract.

    :return:
    """
    prevdir = os.getcwd()
    dirpath = os.path.dirname(os.path.realpath(__file__))
    os.chdir(dirpath)

    subprocess.call(['py.test', '.'])

    os.chdir(prevdir)


if __name__ == '__main__':

    args = argument_parser()
    bbcConfig = setup_config(args)

    if args.command_type == 'auto':
        print("Setting up populus.")
        setup_populus()
        print("Setting up an Ethereum genesis block.")
        setup_genesis(bbcConfig)
        print("Setting up a new Ethereum account.")
        setup_new_account(bbcConfig, args.passphrase)
        print("Starting a local geth node.")
        setup_run(bbcConfig)
        print("Deploying the anchor contract.")
        setup_deploy(bbcConfig)
        print("To stop the local geth node, type 'python setup.py stop'.")

    if args.command_type == 'populus':
        setup_populus()

    elif args.command_type == 'test':
        setup_test()

    elif args.command_type == 'genesis':
        setup_genesis(bbcConfig)

    elif args.command_type == 'new_account':
        setup_new_account(bbcConfig, args.passphrase)

    elif args.command_type == 'account':
        setup_account(bbcConfig, args.address, args.passphrase)

    elif args.command_type == 'run':
        setup_run(bbcConfig)

    elif args.command_type == 'stop':
        setup_stop(bbcConfig)

    elif args.command_type == 'deploy':
        setup_deploy(bbcConfig)

    sys.exit(0)


# end of core/ethereum/setup.py
