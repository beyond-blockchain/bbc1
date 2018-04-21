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


def argument_parser():
    argparser = argparse.ArgumentParser(description='Online domain setting update tool')
    argparser.add_argument('-4', '--ip4address', action='store', default="127.0.0.1", help='bbc_core address (IPv4)')
    argparser.add_argument('-6', '--ip6address', action='store', help='bbc_core address (IPv6)')
    argparser.add_argument('-p', '--port', action='store', default=DEFAULT_CORE_PORT,  help='port number of bbc_core')
    argparser.add_argument('-d', '--domain_id', action='store', default=None, help='domain_id to setup')
    argparser.add_argument('-a', '--add_domain', action='store_true', help='add a new domain')
    argparser.add_argument('-r', '--remove_domain', action='store_true', help='remove a domain')
    argparser.add_argument('-k', '--node_key', action='store', default=None, help='path to node key pem file')
    return argparser.parse_args()


if __name__ == '__main__':
    port = None
    parsed_args = argument_parser()
    if parsed_args.domain_id is None:
        print("### -d option is mandatory!")
        sys.exit(1)

    if parsed_args.ip4address:
        addr = parsed_args.ip4address
    if parsed_args.ip6address:
        addr = parsed_args.ip6address
    port = parsed_args.port
    bbcclient = bbc_app.BBcAppClient(host=addr, port=port, multiq=False, loglevel="all")

    if parsed_args.node_key and os.path.exists(parsed_args.node_key):
        bbcclient.set_node_key(parsed_args.node_key)

    domain_id = bbclib.convert_idstring_to_bytes(parsed_args.domain_id)

    if parsed_args.add_domain:
        bbcclient.domain_setup(domain_id)
        dat = wait_check_result_msg_type(bbcclient.callback, bbclib.MsgType.RESPONSE_SETUP_DOMAIN)
        if KeyType.reason in dat:
            print("Result:", dat[KeyType.reason])
        else:
            print("Result: success")
    elif parsed_args.remove_domain:
        bbcclient.domain_close(domain_id)
        dat = wait_check_result_msg_type(bbcclient.callback, bbclib.MsgType.RESPONSE_CLOSE_DOMAIN)
        if KeyType.reason in dat:
            print("Result:", dat[KeyType.reason])
        else:
            print("Result: success")
    sys.exit(0)
