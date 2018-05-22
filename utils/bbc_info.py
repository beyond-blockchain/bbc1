#!/bin/sh
""":" .

exec python "$0" "$@"
"""
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
import binascii
import json
import pprint

import os
import sys
sys.path.append("../")

from bbc1.core import bbc_app
from bbc1.core.bbc_config import DEFAULT_CORE_PORT
from bbc1.core import bbclib
from bbc1.core.message_key_types import KeyType


def wait_check_result_msg_type(callback, msg_type):
    dat = callback.synchronize()
    if dat[KeyType.command] != msg_type:
        sys.stderr.write("XXXXXX not expected result: %d <=> %d(received)\n" % (msg_type, dat[KeyType.command]))
    return dat


def get_neighborlist(client):
    client.get_domain_list()
    domainlist = client.callback.synchronize()
    for domain_id in domainlist:
        client.get_domain_neighborlist(domain_id=domain_id)
        dat = bbcclient.callback.synchronize()
        print("====== neighbor list of domain:%s =====" % binascii.b2a_hex(domain_id).decode())
        print("         node_id(4byte), ipv4, ipv6, port, is_domain0")
        for k in range(len(dat)):
            node_id, ipv4, ipv6, port, domain0 = dat[k]
            if k == 0:
                print("*myself*    %s, %s, %s, %d, %s" % (binascii.b2a_hex(node_id[:4]), ipv4, ipv6, port, domain0))
            else:
                print("            %s, %s, %s, %d, %s" % (binascii.b2a_hex(node_id[:4]), ipv4, ipv6, port, domain0))


def argument_parser():
    argparser = argparse.ArgumentParser(description='Configure bbc_core using json conf file.')
    argparser.add_argument('-4', '--ip4address', action='store', default="127.0.0.1", help='bbc_core address (IPv4)')
    argparser.add_argument('-6', '--ip6address', action='store', help='bbc_core address (IPv6)')
    argparser.add_argument('-p', '--port', action='store', default=DEFAULT_CORE_PORT,  help='port number of bbc_core')
    argparser.add_argument('-d', '--domain_id', action='store', default=None,  help='domain_id HEX string')
    argparser.add_argument('-l', '--neighborlist', action='store_true', default=False,
                           help='Get neighbor_list in bbc_core')
    argparser.add_argument('-u', '--userlist', action='store_true', default=False, help='Get user_ist in bbc_core')
    argparser.add_argument('-n', '--my_node_id', action='store_true', default=False,  help='Get my node_id')
    argparser.add_argument('--stat', action='store_true', default=False,  help='Get statistics of the bbc_core')
    argparser.add_argument('--getconfig', action='store_true', default=False, help='Get config from bbc_core')
    argparser.add_argument('-k', '--node_key', action='store', default=".bbc1/node_key.pem",
                           help="path to node key pem file")
    return argparser.parse_args()


if __name__ == '__main__':
    parsed_args = argument_parser()
    addr = None
    port = None

    if parsed_args.ip4address:
        addr = parsed_args.ip4address
    if parsed_args.ip6address:
        addr = parsed_args.ip6address
    port = parsed_args.port

    bbcclient = bbc_app.BBcAppClient(host=addr, port=port, multiq=False, loglevel="all")
    if os.path.exists(parsed_args.node_key):
        bbcclient.set_node_key(parsed_args.node_key)

    if parsed_args.getconfig:
        bbcclient.get_bbc_config()
        dat = wait_check_result_msg_type(bbcclient.callback, bbclib.MsgType.RESPONSE_GET_CONFIG)
        print("------ config.json ------")
        conf = json.loads(dat[KeyType.bbc_configuration].decode())
        pprint.pprint(conf, width=80)
        sys.exit(0)

    if parsed_args.stat or (not parsed_args.my_node_id and not parsed_args.userlist and not parsed_args.neighborlist):
        bbcclient.get_stats()
        dat = wait_check_result_msg_type(bbcclient.callback, bbclib.MsgType.RESPONSE_GET_STATS)
        print("------ statistics ------")
        pprint.pprint(dat[KeyType.stats], width=80)
        sys.exit(0)

    if parsed_args.domain_id is None:
        sys.stderr.write("-d option (domain_id) is mandatory\n")
        sys.exit(1)
    domain_id = bbclib.convert_idstring_to_bytes(parsed_args.domain_id)
    bbcclient.set_domain_id(domain_id)

    if parsed_args.my_node_id:
        bbcclient.get_node_id()
        node_id = bbcclient.callback.synchronize()
        print("Node_id is %s" % node_id.hex())
    elif parsed_args.userlist:
        bbcclient.get_user_list()
        user_list = bbcclient.callback.synchronize()
        print("------- user_list -------")
        for uid in user_list:
            print("User_id: ", uid.hex())
    elif parsed_args.neighborlist:
        get_neighborlist(bbcclient)

    sys.exit(0)
