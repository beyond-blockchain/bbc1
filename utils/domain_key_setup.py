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
    argparser = argparse.ArgumentParser(description='Domain_key manager')
    argparser.add_argument('-4', '--ip4address', action='store', default="127.0.0.1", help='bbc_core address (IPv4)')
    argparser.add_argument('-6', '--ip6address', action='store', help='bbc_core address (IPv6)')
    argparser.add_argument('-p', '--port', action='store', default=DEFAULT_CORE_PORT,  help='port number of bbc_core')
    argparser.add_argument('-k', '--node_key', action='store', default=".bbc1/node_key.pem",
                           help="path to node key pem file")
    argparser.add_argument('-dir', '--directory', action='store', default=".bbc-domainkeys",
                           help='Directory for domain_keys')
    argparser.add_argument('-d', '--domain_id', action='store', default=None, help='Domain_id', required=True)
    argparser.add_argument('-g', '--generate', action='store_true', default=False, help='Generate a domain_key')
    argparser.add_argument('-n', '--notify', action='store_true', default=False, help='Notify update of domain_key')
    return argparser.parse_args()


if __name__ == '__main__':
    parsed_args = argument_parser()
    addr = None
    port = None

    if parsed_args.domain_id is None:
        sys.stderr.write("# -d option (domain_id) is mandatory\n")
        sys.exit(1)

    if parsed_args.generate:
        try:
            os.makedirs(parsed_args.directory, exist_ok=True)
        except:
            sys.stderr.write("# Fail to mkdir for domain_keys")
            sys.exit(1)
        keyname = os.path.join(parsed_args.directory, parsed_args.domain_id + ".pem")
        keypair = bbclib.KeyPair()
        keypair.generate()
        with open(keyname, "wb") as fout:
            fout.write(keypair.get_private_key_in_pem())
        sys.exit(0)

    if not parsed_args.notify:
        sys.stderr.write("# Either -g or -n is required\n")
        sys.exit(1)

    if parsed_args.ip4address:
        addr = parsed_args.ip4address
    if parsed_args.ip6address:
        addr = parsed_args.ip6address
    port = parsed_args.port

    bbcclient = bbc_app.BBcAppClient(host=addr, port=port, multiq=False, loglevel="all")
    if os.path.exists(parsed_args.node_key):
        bbcclient.set_node_key(parsed_args.node_key)
    bbcclient.notify_domain_key_update()
    sys.exit(0)
