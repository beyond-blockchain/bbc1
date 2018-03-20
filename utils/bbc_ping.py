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
import ipaddress
sys.path.append("../")

from bbc1.app import bbc_app
from bbc1.core.bbc_config import DEFAULT_CORE_PORT, DEFAULT_P2P_PORT
from bbc1.common import bbclib
from bbc1.common.message_key_types import KeyType
from bbc1.common.bbc_error import *


def wait_check_result_msg_type(callback, msg_type):
    dat = callback.synchronize()
    if dat[KeyType.command] != msg_type:
        sys.stderr.write("XXXXXX not expected result: %d <=> %d(received)\n" % (msg_type, dat[KeyType.command]))
    return dat


def argument_parser():
    argparser = argparse.ArgumentParser(description='Send domain ping to crate domain and static node info.')
    argparser.add_argument('-4', '--ip4address', action='store', help='bbc_core address (IPv4) to control')
    argparser.add_argument('-6', '--ip6address', action='store', help='bbc_core address (IPv6) to control')
    argparser.add_argument('-p', '--port', action='store', default=DEFAULT_CORE_PORT,  help='port number of bbc_core')
    argparser.add_argument('domain_id', action='store', nargs='?', default=None,  help='domain_id string')
    argparser.add_argument('dst_address', action='store', nargs='?', help='destination IPv4/v6 address string')
    argparser.add_argument('dst_port', action='store', nargs='?', default=DEFAULT_P2P_PORT+1,  help='port number')
    return argparser.parse_args()


def send_domain_ping(bbcclient, domain_id, addr, port):
    dst_ip, dst_port = ipaddress.ip_address(addr), int(port)
    ipv4 = None
    ipv6 = None
    if isinstance(dst_ip, ipaddress.IPv4Address):
        ipv4 = str(dst_ip)
    else:
        ipv6 = str(dst_ip)
    print("Request domain_ping to %s, %s, %d" % (ipv4, ipv6, dst_port))
    bbcclient.send_domain_ping(domain_id, ipv4, ipv6, dst_port)


if __name__ == '__main__':
    port = None
    parsed_args = argument_parser()
    addr = "127.0.0.1"
    if parsed_args.ip4address:
        addr = parsed_args.ip4address
    if parsed_args.ip6address:
        addr = parsed_args.ip6address
    port = parsed_args.port

    bbcclient = bbc_app.BBcAppClient(host=addr, port=port, loglevel="all")

    domain_id = bbclib.convert_idstring_to_bytes(parsed_args.domain_id)
    bbcclient.domain_setup(domain_id, "simple_cluster")
    dat = wait_check_result_msg_type(bbcclient.callback, bbclib.ServiceMessageType.RESPONSE_SETUP_DOMAIN)
    assert dat[KeyType.status] == ESUCCESS

    send_domain_ping(bbcclient, domain_id, parsed_args.dst_address, parsed_args.dst_port)

    print("*** wait 5 sec, checking peer_list in the core ***")
    time.sleep(5)
    bbcclient.get_domain_peerlist(domain_id=domain_id)
    dat = bbcclient.callback.synchronize()
    print("====== peer list =====")
    for k in range(len(dat)):
        node_id, ipv4, ipv6, port = dat[k]
        if k == 0:
            print("*myself*    %s, %s, %s, %d" % (binascii.b2a_hex(node_id[:4]), ipv4, ipv6, port))
        else:
            print("            %s, %s, %s, %d" % (binascii.b2a_hex(node_id[:4]), ipv4, ipv6, port))

    sys.exit(0)
