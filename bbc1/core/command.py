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
from argparse import ArgumentParser
import sys
sys.path.extend(["../../"])
from bbc1.core.bbc_config import DEFAULT_CORE_PORT, DEFAULT_P2P_PORT


DEFAULT_SERV_ADDR = '127.0.0.1'


def parser():
    usage = 'python {} [--coreport <number>] [--p2pport <number>] [--workingdir <dir>] ' \
            '[--config <filename>] [--default_config <filename>] [--nodekey] [--no_nodekey] [--domain0] ' \
            '[--ledgersubsystem] [--ip4addr <IP addr>] [--ip6addr <IPv6 addr>] ' \
            '[--log <filename>] [--verbose_level <string>] [--daemon] [--kill] [--help]'.format(__file__)
    argparser = ArgumentParser(usage=usage)
    argparser.add_argument('-cp', '--coreport', type=int, default=DEFAULT_CORE_PORT, help='waiting TCP port')
    argparser.add_argument('-pp', '--p2pport', type=int, default=DEFAULT_P2P_PORT, help='waiting TCP port')
    argparser.add_argument('-w', '--workingdir', type=str, default=".bbc1", help='working directory name')
    argparser.add_argument('-c', '--config', type=str, default=None, help='config file name')
    argparser.add_argument('--default_config', type=str, default=None, help='default config file')
    argparser.add_argument('--nodekey', action='store_true', help='use node_key for admin command')
    argparser.add_argument('--no_nodekey', action='store_true', help='don\'t use node_key for admin command')
    argparser.add_argument('--domain0', action='store_true', help='connect to domain_global_0')
    argparser.add_argument('--ledgersubsystem', action='store_true', help='use ledger_subsystem')
    argparser.add_argument('--ip4addr', type=str, default=None, help='IPv4 address exposed to the external network')
    argparser.add_argument('--ip6addr', type=str, default=None, help='IPv6 address exposed to the external network')
    argparser.add_argument('-l', '--log', type=str, default="-", help='log filename/"-" means STDOUT')
    argparser.add_argument('-d', '--daemon', action='store_true', help='run in background')
    argparser.add_argument('-k', '--kill', action='store_true', help='kill the daemon')
    argparser.add_argument('-v', '--verbose_level', type=str, default="debug",
                           help='log level all/debug/info/warning/error/critical/none')
    args = argparser.parse_args()
    return args
