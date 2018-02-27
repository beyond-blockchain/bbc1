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
    argparser.add_argument('-4', '--ip4address', action='store', default="127.0.0.1", help='bbc_core address (IPv4)')
    argparser.add_argument('-6', '--ip6address', action='store', help='bbc_core address (IPv6)')
    argparser.add_argument('-p', '--port', action='store', default=DEFAULT_CORE_PORT,  help='port number of bbc_core')
    argparser.add_argument('-d', '--domain_id', action='store', default=None, help='domain_id to setup')
    argparser.add_argument('--ping_to_neighbors', action='store_true', help='make the bbc_core send ping to all '
                                                                           'neighbors')
    argparser.add_argument('-i', '--id', action='store',  help='SHA256 ID calculation from the given strings')
    argparser.add_argument('-t', '--timebaseid', action='store',  help='SHA256 ID calculation from the given strings including timestamp')
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
    if parsed_args.domain_id is None:
        print("### -d option is mandatory!")
        sys.exit(1)
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

    domain_id = bbclib.convert_idstring_to_bytes(parsed_args.domain_id)

    if parsed_args.ping_to_neighbors:
        print("ping to all neighbor bbc_cores")
        bbcclient.ping_to_all_neighbors(domain_id)
        time.sleep(1)
        sys.exit(0)

    bbcclient.domain_setup(domain_id, "simple_cluster")
    dat = wait_check_result_msg_type(bbcclient.callback, bbclib.ServiceMessageType.RESPONSE_SETUP_DOMAIN)
    assert dat[KeyType.status] == ESUCCESS

    sys.exit(0)
