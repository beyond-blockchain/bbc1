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
import time
import binascii
import sys
import os
import ipaddress
sys.path.append("../")

from bbc1.core import bbc_app
from bbc1.core.bbc_config import DEFAULT_CORE_PORT, DEFAULT_P2P_PORT
from bbc1.core import bbclib
from bbc1.core.message_key_types import KeyType
from bbc1.core.bbc_error import *


def argument_parser():
    argparser = argparse.ArgumentParser(description='Send domain ping to crate domain and configure static '
                                                    'neighbor nodes.')
    argparser.add_argument('-4', '--ip4address', action='store', help='bbc_core address (IPv4) to connect')
    argparser.add_argument('-6', '--ip6address', action='store', help='bbc_core address (IPv6) to connect')
    argparser.add_argument('-p', '--port', action='store', default=DEFAULT_CORE_PORT,  help='port number of bbc_core')
    argparser.add_argument('-k', '--node_key', action='store', default=".bbc1/node_key.pem",
                           help="path to node key pem file")
    argparser.add_argument('domain_id', action='store', nargs='?', default=None,  help='Hex string of the domain_id')
    argparser.add_argument('dst_address', action='store', nargs='?',
                           help='destination IPv4/v6 address of the neighbor node')
    argparser.add_argument('dst_port', action='store', nargs='?', default=DEFAULT_P2P_PORT+1,
                           help='destination port number of the neighbor node')
    return argparser.parse_args()


def send_domain_ping(client, dom_id, adr, pt):
    dst_ip, dst_port = ipaddress.ip_address(adr), int(pt)
    ip4 = None
    ip6 = None
    if isinstance(dst_ip, ipaddress.IPv4Address):
        ip4 = str(dst_ip)
    else:
        ip6 = str(dst_ip)
    print("Request domain_ping to %s, %s, %d" % (ip4, ip6, dst_port))
    client.send_domain_ping(dom_id, ip4, ip6, dst_port)


if __name__ == '__main__':
    parsed_args = argument_parser()
    addr = "127.0.0.1"
    if parsed_args.ip4address:
        addr = parsed_args.ip4address
    if parsed_args.ip6address:
        addr = parsed_args.ip6address
    port = parsed_args.port

    bbcclient = bbc_app.BBcAppClient(host=addr, port=port, multiq=False, loglevel="all")
    if os.path.exists(parsed_args.node_key):
        bbcclient.set_node_key(parsed_args.node_key)

    domain_id = bbclib.convert_idstring_to_bytes(parsed_args.domain_id)
    query_id = bbcclient.domain_setup(domain_id)
    dat = bbcclient.callback.synchronize()
    assert dat[KeyType.status] == ESUCCESS

    send_domain_ping(bbcclient, domain_id, parsed_args.dst_address, parsed_args.dst_port)

    print("*** wait 5 sec, checking neighbor list in the core ***")
    time.sleep(5)
    query_id = bbcclient.get_domain_neighborlist(domain_id=domain_id)
    dat = bbcclient.callback.synchronize()
    print("====== neighbor list =====")
    for k in range(len(dat)):
        node_id, ipv4, ipv6, port, domain0 = dat[k]
        if k == 0:
            print("*my_self*   %s, %s, %s, %d, domain0:%s" % (binascii.b2a_hex(node_id[:4]), ipv4, ipv6, port, domain0))
        else:
            print("            %s, %s, %s, %d, domain0:%s" % (binascii.b2a_hex(node_id[:4]), ipv4, ipv6, port, domain0))
    sys.exit(0)
