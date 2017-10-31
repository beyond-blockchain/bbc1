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
import sys
sys.path.append("../")

from bbc1.app import bbc_app
from bbc1.core.bbc_config import DEFAULT_CORE_PORT
from bbc1.common import bbclib
from bbc1.common.message_key_types import KeyType


domain_id = bbclib.get_new_id("test_domain", include_timestamp=False)
user_id = bbclib.get_new_id("dummy_user_name")


def wait_check_result_msg_type(callback, msg_type):
    dat = callback.synchronize()
    if dat[KeyType.command] != msg_type:
        sys.stderr.write("XXXXXX not expected result: %d <=> %d(received)\n" % (msg_type, dat[KeyType.command]))
    return dat


def argument_parser():
    argparser = argparse.ArgumentParser(description='Register/Verify transaction in the ledger subsystem.')
    argparser.add_argument('-4', '--ip4address', action='store', default="127.0.0.1", help='bbc_core address (IPv4)')
    argparser.add_argument('-6', '--ip6address', action='store', help='bbc_core address (IPv6)')
    argparser.add_argument('-p', '--port', action='store', default=DEFAULT_CORE_PORT,  help='port number of bbc_core')
    argparser.add_argument('-a', '--asset_group_id', action='store', help='asset_group_id you want to treat')
    argparser.add_argument('-t', '--transaction_id', action='store', help='target transaction_id')
    argparser.add_argument('--register', action='store_true',  help='register transaction_id in the ledger_subsystem')
    argparser.add_argument('--verify', action='store_true',  help='verify transaction_id in the ledger_subsystem')
    argparser.add_argument('--start', action='store_true',  help='start ledger_subsystem')
    argparser.add_argument('--stop', action='store_true',  help='stop ledger_subsystem')
    return argparser.parse_args()


if __name__ == '__main__':
    port = None
    parsed_args = argument_parser()
    if parsed_args.ip4address:
        addr = parsed_args.ip4address
        v4flag = True
    if parsed_args.ip6address:
        addr = parsed_args.ip6address
        v4flag = False
    port = parsed_args.port

    bbcclient = bbc_app.BBcAppClient(host=addr, port=port, loglevel="all")
    bbcclient.set_user_id(user_id)

    if parsed_args.start or parsed_args.stop:
        bbcclient.manipulate_ledger_subsystem(parsed_args.start)
        dat = wait_check_result_msg_type(bbcclient.callback, bbclib.ServiceMessageType.RESPONSE_MANIP_LEDGER_SUBSYS)
        print("Done")
        sys.exit(0)

    if parsed_args.asset_group_id is not None and parsed_args.transaction_id is not None:
        asset_group_id = bbclib.convert_idstring_to_bytes(parsed_args.asset_group_id)
        transaction_id = bbclib.convert_idstring_to_bytes(parsed_args.transaction_id)

        bbcclient.domain_setup(domain_id)
        bbcclient.callback.synchronize()

        bbcclient.set_asset_group_id(asset_group_id)
        bbcclient.register_asset_group(domain_id=domain_id, asset_group_id=asset_group_id)
        bbcclient.callback.synchronize()
        bbcclient.register_to_core()

        if parsed_args.verify:
            print("--> Try to verify")
            bbcclient.verify_in_ledger_subsystem(asset_group_id, transaction_id)
            dat = wait_check_result_msg_type(bbcclient.callback,
                                             bbclib.ServiceMessageType.RESPONSE_VERIFY_HASH_IN_SUBSYS)
            print(dat[KeyType.markle_tree])  # TODO: Please modify here (how to treat the result)
            print("Done")
        elif parsed_args.register:
            print("--> Try to register")
            bbcclient.register_in_ledger_subsystem(asset_group_id, transaction_id)
            dat = wait_check_result_msg_type(bbcclient.callback,
                                             bbclib.ServiceMessageType.RESPONSE_REGISTER_HASH_IN_SUBSYS)
            print("Done")
    sys.exit(0)
