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
import json
import binascii

import os
import sys
sys.path.append("../")

from bbc1.app import bbc_app
from bbc1.core.bbc_config import DEFAULT_CORE_PORT
from bbc1.common import bbclib
from bbc1.common.message_key_types import KeyType
from bbc1.common.bbc_error import *


def wait_check_result_msg_type(callback, msg_type):
    dat = callback.synchronize()
    if dat[KeyType.command] != msg_type:
        sys.stderr.write("XXXXXX not expected result: %d <=> %d(received)\n" % (msg_type, dat[KeyType.command]))
    return dat


def output_template_config():
    conf =  {
        '*domain_id': {
            'module': 'simple_cluster',
            'static_nodes': {
                '*node_id' : "[*ipv4, *ipv6, *port]"
            },
            'asset_group_ids': {
                '*asset_group_id1': {
                    'storage_type': 1,
                    'storage_path': None,
                    'advertise_in_domain0': False,
                },
                '*asset_group_id2': {
                    'storage_type': 1,
                    'storage_path': None,
                    'advertise_in_domain0': False,
                }
            }
        }
    }
    print(json.dumps(conf, indent=4))
    sys.stderr.write("\n# *xxx_id must be 64-character HEX string\n")
    sys.stderr.write("# *ipv4 and *ipv6 must be an address string\n")
    sys.stderr.write("# *port must be an integer\n")
    sys.stderr.write("# value selection of stroage_type: 0(=Not stored in bbc_core),"
                     " 1(=stored in filesystem of bbc_core)\n")


def get_config(client):
    client.get_bbc_config()
    dat = wait_check_result_msg_type(client.callback, bbclib.ServiceMessageType.RESPONSE_GET_CONFIG)
    return dat[KeyType.bbc_configuration].decode()


def send_config(client, config_obj):
    for domain_id_str, conf in config_obj.items():
        domain_id = bbclib.convert_idstring_to_bytes(domain_id_str)

        client.domain_setup(domain_id, conf['module'])
        dat = wait_check_result_msg_type(client.callback, bbclib.ServiceMessageType.RESPONSE_SETUP_DOMAIN)
        assert dat[KeyType.status] == ESUCCESS

        for nd, info in conf['static_nodes'].items():
            node_id, ipv4, ipv6, port = nd, info[0], info[1], info[2]
            client.set_domain_static_node(domain_id, bbclib.convert_idstring_to_bytes(node_id), ipv4, ipv6, port)
            dat = wait_check_result_msg_type(client.callback, bbclib.ServiceMessageType.RESPONSE_SET_STATIC_NODE)
            assert dat[KeyType.status] == ESUCCESS

        for asset_group_id_str, info in conf['asset_group_ids'].items():
            asset_group_id = bbclib.convert_idstring_to_bytes(asset_group_id_str)
            client.register_asset_group(domain_id=domain_id, asset_group_id=asset_group_id,
                                        storage_type=info['storage_type'], storage_path=info['storage_path'],
                                        advertise_in_domain0=info['advertise_in_domain0']
                                        )
            dat = wait_check_result_msg_type(client.callback, bbclib.ServiceMessageType.RESPONSE_SETUP_ASSET_GROUP)
            assert dat[KeyType.status] == ESUCCESS


def get_mynodeinfo(client):
    conf = json.loads(get_config(client))
    mynode_conf = {}
    for domain_id_str in conf['domains'].keys():
        domain_id = bbclib.convert_idstring_to_bytes(domain_id_str)
        client.get_domain_peerlist(domain_id)
        results = client.callback.synchronize()
        if results is None:
            continue
        node_id_str = bbclib.convert_id_to_string(results[0][0])
        mynode_conf.setdefault(domain_id_str, dict())[node_id_str] = (results[0][1], results[0][2], results[0][3])
    print("## {'domain_id': {'node_id': (IPv4, IPv6, port)}}")
    print(mynode_conf)


def get_peerlist(client):
    client.get_domain_list()
    domainlist = bbcclient.callback.synchronize()
    for domain_id in domainlist:
        print(domain_id)
        client.get_domain_peerlist(domain_id=domain_id)
        dat = bbcclient.callback.synchronize()
        print("====== peer list of domain:%s =====" % binascii.b2a_hex(domain_id).decode())
        for k in range(len(dat)):
            node_id, ipv4, ipv6, port = dat[k]
            if k == 0:
                print("*myself*    %s, %s, %s, %d" % (binascii.b2a_hex(node_id[:4]), ipv4, ipv6, port))
            else:
                print("            %s, %s, %s, %d" % (binascii.b2a_hex(node_id[:4]), ipv4, ipv6, port))


def argument_parser():
    argparser = argparse.ArgumentParser(description='Configure bbc_core using json conf file.')
    argparser.add_argument('-4', '--ip4address', action='store', default="127.0.0.1", help='bbc_core address (IPv4)')
    argparser.add_argument('-6', '--ip6address', action='store', help='bbc_core address (IPv6)')
    argparser.add_argument('-p', '--port', action='store', default=DEFAULT_CORE_PORT,  help='port number of bbc_core')
    argparser.add_argument('-c', '--config', action='store_true', default=False,  help='Create template config file')
    argparser.add_argument('-g', '--getconfig', action='store_true', default=False, help='Get config file from bbc_core')
    argparser.add_argument('-l', '--getpeerlist', action='store_true', default=False, help='Get peer_list in bbc_core')
    argparser.add_argument('-m', '--mynodeid', action='store_true', default=False,  help='Get my node_id')
    argparser.add_argument('-i', '--id', action='store',  help='SHA256 ID calculation from the given strings')
    argparser.add_argument('-t', '--timebaseid', action='store',  help='SHA256 ID calculation from the given strings '
                                                                       'including timestamp')
    argparser.add_argument('file', action='store', nargs='?', default=None,  help='Json config file')
    return argparser.parse_args()


if __name__ == '__main__':
    parsed_args = argument_parser()
    addr = None
    port = None

    if parsed_args.config:
        output_template_config()
        sys.exit(0)
    if parsed_args.id:
        value = bbclib.get_new_id(parsed_args.id, include_timestamp=False)
        print(bbclib.convert_id_to_string(value))
        sys.exit(0)
    if parsed_args.timebaseid:
        value = bbclib.get_new_id(parsed_args.id, include_timestamp=True)
        print(bbclib.convert_id_to_string(value))
        sys.exit(0)

    if parsed_args.ip4address:
        addr = parsed_args.ip4address
    if parsed_args.ip6address:
        addr = parsed_args.ip6address
    port = parsed_args.port
    bbcclient = bbc_app.BBcAppClient(host=addr, port=port, loglevel="all")

    if parsed_args.getconfig:
        print(get_config(bbcclient))
    elif parsed_args.mynodeid:
        get_mynodeinfo(bbcclient)
    elif parsed_args.getpeerlist:
        get_peerlist(bbcclient)
    elif parsed_args.file:
        if os.path.exists(parsed_args.file):
            with open(parsed_args.file, "r") as f:
                config = json.load(f)
            send_config(bbcclient, config)
        else:
            print("No such file")
            sys.exit(1)

    sys.exit(0)
