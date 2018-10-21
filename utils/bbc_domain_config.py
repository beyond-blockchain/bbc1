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

import os
import sys
import json
import pprint
from argparse import ArgumentParser
sys.path.append("../")
from bbc1.core.bbc_config import DEFAULT_WORKING_DIR, DEFAULT_CONFIG_FILE

default_config = {
    "workingdir": ".bbc1",
    "client": {
        "port": 9000,
        "use_node_key": True,
    },
    "network": {
        "p2p_port": 6641,
        "max_connections": 100,
    },
    "domain_key": {
        "use": False,
        "directory": ".bbc1/domain_keys",
        "obsolete_timeout": 300,
    },
    "domains": {
        "0000000000000000000000000000000000000000000000000000000000000000": {
            "module": "p2p_domain0",
            "static_nodes": {},
            "use_ledger_subsystem": False,
            "ledger_subsystem": {
                "subsystem": "ethereum",
                "max_transactions": 4096,
                "max_seconds": 3600,
            }
        }
    },
    'domain_default': {
        'storage': {
            "type": "internal",  # or "external"
        },
        'db': {
            "db_type": "sqlite",  # or "mysql"
            "db_name": "bbc_ledger.sqlite",
            "replication_strategy": "all",  # or "p2p"/"external" (valid only in db_type=mysql)
            "db_servers": [{"db_addr": "127.0.0.1", "db_port": 3306, "db_user": "user", "db_pass": "pass"}]
            # valid only in the case of db_type=mysql
        },
        'static_nodes': {
            # id : [ipv4, ipv6, port]
        },
    },
    "ethereum": {
        "chain_id": 15,
        "port": 30303,
        "log": "geth.log",
        "account": "",
        "passphrase": "",
        "contract": "BBcAnchor",
        "contract_address": "",
    }
}


def parser():
    usage = 'python -t <generate|write|delete> -d <DOMAIN_HEX> -k1 <K1NAME> -v <K1VALUE> [-k2 <K2NAME>] [-v2 ' \
            '<K2VALUE>] -w <WORKINGDIR>'
    argparser = ArgumentParser(usage=usage)
    argparser.add_argument('-t', '--type', type=str, choices=['generate', 'write', 'delete'],
                           default=None, help='operation type', required=True)
    argparser.add_argument('-d', '--domainhex', type=str, default=None, help='domain hex', required=False)
    argparser.add_argument('-k1', '--key1name', type=str, default=None, help='key1 name', required=False)
    argparser.add_argument('-v', '--value', type=str, default=None, help='value', required=False)
    argparser.add_argument('-k2', '--key2name', type=str, default=None, help='key2 name', required=False)
    argparser.add_argument('-w', '--workingdir', type=str, default=DEFAULT_WORKING_DIR, help='working directory', required=False)
    args = argparser.parse_args()

    return args


def isJsonFormat(line):
    if line is None:
        return None
    try:
        json.loads(line)
    except json.JSONDecodeError as e:
        print(sys.exc_info())
        print(e)
        return False
    except ValueError as e:
        print(sys.exc_info())
        print(e)
        return False
    except Exception as e:
        print(sys.exc_info())
        print(e)
        return False
    return True


def convertValue(str):
    if isJsonFormat(str):
        dictobj = json.loads(str)
        return dictobj
    else:
        if str is None:
            return None
        elif str.upper() == 'TRUE':
            return True
        elif str.upper() == 'FALSE':
            return False
        else:
            return str


def convertKeyValue(name, value):
    obj = {}
    obj["key"] = name
    obj["value"] = convertValue(value)
    return obj


def getTargetFile(working_dir):
    filepath = os.path.join(working_dir, DEFAULT_CONFIG_FILE)
    print("input filepath : %s" % filepath)
    if os.path.exists(filepath):
        return filepath
    else:
        return None


def getOutputFilepath(working_dir):
    filepath = os.path.join(working_dir, DEFAULT_CONFIG_FILE)
    return filepath


def fetchTargetObj(filepath):
    if filepath is not None and os.path.exists(filepath):
        with open(filepath, 'r') as f:
            print("load from %s" % filepath)
            targetObj = json.load(f)
    else:
        print("load from default")
        targetObj = default_config
    return targetObj


def file_output(filepath, targetobj):
    try:
        with open(filepath, "w") as f:
            f.write(json.dumps(targetobj))
    except:
        print("failed file_output : %s" % filepath)
        return False
    return True


def write_proc(targetobj, domainhex, k1obj, k2obj, filepath):
    print("------")
    if k1obj['value'] is None and k2obj['value'] is None:
        targetobj["domains"][domainhex] = default_config['domain_default']
        pprint.pprint(targetobj, width=80)
        return file_output(filepath, targetobj)
    if k2obj['key'] is not None and k1obj['key'] is None:
        print("k2 is not None and k1 is None")
        return False
    if domainhex is not None:
        if domainhex not in targetobj["domains"]:
            print("domainhex is not exist : %s" % domainhex)
            return False
        if k1obj['key'] is not None:
            if k2obj['key'] is not None:
                print("create k2")
                targetobj["domains"][domainhex][k1obj["key"]][k2obj["key"]] = k2obj["value"]
            else:
                print("create k1")
                targetobj["domains"][domainhex][k1obj["key"]] = k1obj["value"]
        else:
            print("create domainhex (do nothing)")
    else:
        print("invalid domainhex : %s" % domainhex)
        return False
    pprint.pprint(targetobj, width=80)
    return file_output(filepath, targetobj)


def delete_proc(targetobj, domainhex, k1obj, k2obj, filepath):
    print("------")
    if domainhex is not None:
        if k1obj['key'] is not None:
            if k2obj['key'] is not None:
                if k2obj["key"] in targetobj["domains"][domainhex][k1obj["key"]]:
                    print("delete k2")
                    targetobj["domains"][domainhex][k1obj["key"]].pop(k2obj["key"])
                else:
                    print("delete k2, but does not have key : %s" % k2obj["key"])
                    return False
            else:
                if k1obj["key"] in targetobj["domains"][domainhex]:
                    print("delete k1")
                    targetobj["domains"][domainhex].pop(k1obj["key"])
                else:
                    print("delete k1, but does not have key : %s" % k1obj["key"])
                    return False
        else:
            if domainhex in targetobj["domains"]:
                print("delete domainhex")
                targetobj["domains"].pop(domainhex)
            else:
                print("delete domainhex, but does not have key : %s" % domainhex)
                return False
    pprint.pprint(targetobj, width=80)
    return file_output(filepath, targetobj)


if __name__ == '__main__':
    try:
        argresult = parser()
    except Exception as e:
        print("failed to parse")
        sys.exit(1)

    if not os.path.exists(argresult.workingdir):
        os.makedirs(argresult.workingdir)

    domainhex = argresult.domainhex
    fpath = getTargetFile(argresult.workingdir)
    print("fpath:", fpath)
    outputfpath = getOutputFilepath(argresult.workingdir)
    print("outputfpath:", fpath)
    targetobj = fetchTargetObj(fpath)

    if argresult.type == 'generate':
        file_output(outputfpath, targetobj)
        sys.exit(0)

    if argresult.key1name is None and argresult.key2name is None:
        k1obj = convertKeyValue(None, None)
        k2obj = convertKeyValue(None, None)
    elif argresult.key2name is None:
        k1obj = convertKeyValue(argresult.key1name, argresult.value)
        k2obj = convertKeyValue(None, None)
    else:
        k1obj = convertKeyValue(argresult.key1name, None)
        k2obj = convertKeyValue(argresult.key2name, argresult.value)

    if argresult.type == 'write':
        if not write_proc(targetobj, domainhex, k1obj, k2obj, outputfpath):
            print("Failed to write the entry...")
            sys.exit(1)
    elif argresult.type == 'delete':
        if not delete_proc(targetobj, domainhex, k1obj, k2obj, outputfpath):
            print("Failed to delete the entry...")
            sys.exit(1)

    sys.exit(0)
