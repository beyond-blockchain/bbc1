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
from threading import RLock
from collections import Mapping

import sys
sys.path.extend(["../../"])
from bbc1.core import bbclib


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
        'use_node_key': True,
    },
    'network': {
        'p2p_port': DEFAULT_P2P_PORT,
        'max_connections': 100,
    },
    'domain_key': {
        'use': False,
        'directory': DEFAULT_WORKING_DIR+"/domain_keys",
        'obsolete_timeout': 300,
    },
    'domains': {
        '0000000000000000000000000000000000000000000000000000000000000000': {
            'module': 'p2p_domain0',
            'static_nodes': {
                # id : [ipv4, ipv6, port]
            },
            'use_ledger_subsystem': False,  # if this items does not exist or False, ledger_subsystem will not be used
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


def update_deep(d, u):
    for k, v in u.items():
        # this condition handles the problem
        if not isinstance(d, Mapping):
            d = u
        elif isinstance(v, Mapping):
            r = update_deep(d.get(k, {}), v)
            d[k] = r
        else:
            d[k] = u[k]

    return d


class BBcConfig:
    def __init__(self, directory=None, file=None):
        self.config = copy.deepcopy(current_config)
        if directory is not None:
            self.working_dir = directory
            self.config['workingdir'] = self.working_dir
        else:
            self.working_dir = self.config['workingdir']
        if file is not None:
            self.config_file = file
        else:
            self.config_file = os.path.join(self.working_dir, DEFAULT_CONFIG_FILE)

        if not os.path.exists(self.working_dir):
            os.mkdir(self.working_dir)

        if os.path.isfile(self.config_file):
            update_deep(self.config, self.read_config())
        self.update_config()

    def read_config(self):
        config = dict()
        with open(self.config_file, "r") as f:
            try:
                config = json.load(f)
            except:
                print("config file must be in JSON format")
                os._exit(1)
        return config

    def update_config(self):
        try:
            with open(self.config_file, "w") as f:
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
        conf = self.read_config()
        if 'domains' in conf and domain_id_str in conf['domains']:
            self.config['domains'][domain_id_str] = conf['domains'][domain_id_str]

        if create_if_new and domain_id_str not in self.config['domains']:
            self.config['domains'][domain_id_str] = {
                'storage': {
                    "type": "internal",  # or "external"
                },
                'db': {
                    "db_type": "sqlite",            # or "mysql"
                    "db_name": "bbc_ledger.sqlite",
                    "replication_strategy": "all",  # or "p2p"/"external" (valid only in db_type=mysql)
                    "db_servers": [{"db_addr": "127.0.0.1", "db_port": 3306, "db_user": "user", "db_pass": "pass"}]
                    # valid only in the case of db_type=mysql
                },
                'static_nodes': {
                    # id : [ipv4, ipv6, port]
                },
            }
        if domain_id_str in self.config['domains']:
            return self.config['domains'][domain_id_str]
        return None

    def remove_domain_config(self, domain_id):
        domain_id_str = bbclib.convert_id_to_string(domain_id)
        if domain_id_str in self.config['domains']:
            del self.config['domains'][domain_id_str]
            self.update_config()

