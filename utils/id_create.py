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
import sys
sys.path.append("../")

from bbc1.core import bbclib


def argument_parser():
    argparser = argparse.ArgumentParser(description='Calculate ID HEX string from name')
    argparser.add_argument('-s', '--string', action='store',  help='Seed strings for calculating SHA256')
    argparser.add_argument('-t', '--timebaseid', action='store_true', default=False, help='Concatenate timestamp with seed strings')
    argparser.add_argument('-r', '--random', action='store_true',  help='Seed strings for calculating SHA256')
    return argparser.parse_args()


if __name__ == '__main__':
    parsed_args = argument_parser()

    if parsed_args.string:
        value = bbclib.get_new_id(parsed_args.string, include_timestamp=parsed_args.timebaseid)
        print(bbclib.convert_id_to_string(value))
        sys.exit(0)

    if parsed_args.random:
        value = bbclib.get_random_id()
        print(bbclib.convert_id_to_string(value))
        sys.exit(0)

    sys.stderr.write("# Either -s or -r is required\n")
    sys.exit(1)
