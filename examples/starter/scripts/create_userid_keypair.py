#!/bin/sh
""":" .

exec python "$0" "$@"
"""
# -*- coding: utf-8 -*-
"""
Copyright (c) 2018 beyond-blockchain.org.

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
import sys
import argparse

from bbc1.core import bbclib


PRIVATE_KEY = ".private_key"
PUBLIC_KEY = ".public_key"


def create_keypair():
    keypair = bbclib.KeyPair()
    keypair.generate()
    with open(PRIVATE_KEY, "wb") as fout:
        fout.write(keypair.private_key)
    with open(PUBLIC_KEY, "wb") as fout:
        fout.write(keypair.public_key)
    print("created private_key and public_key : %s, %s" % (PRIVATE_KEY, PUBLIC_KEY))


def argument_parser():
    argparser = argparse.ArgumentParser(description='Generate an user_id')
    argparser.add_argument('-u', '--username', action='store', help='username')
    return argparser.parse_args()


if __name__ == '__main__':
    if os.path.exists(PRIVATE_KEY):
        print("Private key file already exists.")
        sys.exit(1)
    parsed_args = argument_parser()
    if parsed_args.username is None:
        print("Usage: $0 -u username")
        sys.exit(1)
    create_keypair()
    user_id = bbclib.get_new_id(parsed_args.username, include_timestamp=False)
    with open("ID_FILE", "w") as f:
        f.write('{\n  "name": "%s",\n  "id": "%s"\n}\n' % (parsed_args.username, user_id.hex()))
