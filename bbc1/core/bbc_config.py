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
import os
import json
import copy

import sys
sys.path.extend(["../../"])
from bbc1.common import bbclib
from bbc1.common.bbclib import StorageType


DEFAULT_WORKING_DIR = '.bbc1'
DEFAULT_CONFIG_FILE = 'config.json'
DEFAULT_CORE_PORT = 9000
DEFAULT_P2P_PORT = 6641
DEFAULT_ETHEREUM_LOG_FILE = 'geth.log'
DEFAULT_ETHEREUM_CHAIN_ID = 15
DEFAULT_ETHEREUM_GETH_PORT = 30303

TIMEOUT_TIMER = 3

current_config = {
    'workingdir': DEFAULT_WORKING_DIR,
    'client': {
        'port': DEFAULT_CORE_PORT,
    },
    'ledger': {
        'type': "sqlite3",
        'transaction_db': "bbc_transaction.sqlite3",
        'auxiliary_db': "bbc_aux.sqlite3",
        'merkle_db': "bbc_merkle.sqlite3",
    },
    'storage': {
        #'path': "path/to/somewhere",
        #'path': "/path/to/somewhere",
    },
    'network': {
        'p2p_port': DEFAULT_P2P_PORT,
        'max_connections': 100,
        'modules': {
            'simple_cluster': {
                'test': 1,
            },
            'p2p_kademlia': {
                'concurrent_lookup_num': 3,
                'redundancy': 3,
                'k_value': 10,
            },
        },
    },
    'domains': {
        '0000000000000000000000000000000000000000000000000000000000000000': {
            'module': 'p2p_domain0',
            'static_nodes': {
                # id : [ipv4, ipv6, port]
            },
            'peer_list': {
                # id : [ipv4, ipv6, port]
            },
        },
    },
    'use_ledger_subsystem': False,
    'ethereum': {
        'chain_id': DEFAULT_ETHEREUM_CHAIN_ID,
        'port': DEFAULT_ETHEREUM_GETH_PORT,
        'log': DEFAULT_ETHEREUM_LOG_FILE,
        'account': '',
        'passphrase': '',
        'contract': 'BBcAnchor',
        'contract_address': '',
    },
    'ledger_subsystem': {
        'subsystem': 'ethereum',
        'max_transactions': 4096,
        'max_seconds': 60 * 60,
    },
}


class BBcConfig:
    def __init__(self, directory=None, file=None):
        self.config = copy.deepcopy(current_config)
        self.config_file = DEFAULT_CONFIG_FILE
        self.working_dir = self.config['workingdir']
        if directory is not None:
            self.working_dir = directory
            self.config['workingdir'] = self.working_dir
        if file is not None:
            self.config_file = file

        if not os.path.exists(self.working_dir):
            os.mkdir(self.working_dir)

        if os.path.isfile(os.path.join(self.working_dir, self.config_file)):
            with open(os.path.join(self.working_dir, self.config_file), "r") as f:
                try:
                    self.config.update(json.load(f))
                except:
                    print("config file must be in JSON format")
                    os._exit(1)
        self.update_config()

    def update_config(self):
        try:
            with open(os.path.join(self.working_dir, self.config_file), "w") as f:
                json.dump(self.config, f, indent=4)
            return True
        except:
            import traceback
            traceback.print_exc()
            return False

    def get_json_config(self):
        self.update_config()
        return json.dumps(self.config, indent=2)

    def get_config(self):
        return self.config

    def get_domain_config(self, domain_id, create_if_new=False):
        domain_id_str = bbclib.convert_id_to_string(domain_id)
        if create_if_new and domain_id_str not in self.config['domains']:
            self.config['domains'][domain_id_str] = {
                'module': 'simple_cluster',
                'static_nodes': {
                    # id : [ipv4, ipv6, port]
                },
                'peer_list': {
                    # id : [ipv4, ipv6, port]
                },
            }
        if domain_id_str in self.config['domains']:
            return self.config['domains'][domain_id_str]
        return None
