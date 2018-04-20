import os
import sys
import json
from argparse import ArgumentParser
sys.path.append("../")
from bbc1.core.bbc_config import DEFAULT_WORKING_DIR, DEFAULT_CONFIG_FILE

DEFAULT_JSON = '\
{\
    "workingdir": ".bbc1",\
    "client": {\
        "port": 9000\
    },\
    "network": {\
        "p2p_port": 6641,\
        "max_connections": 100\
    },\
    "domain_auth_key": {\
        "use": false,\
        "directory": ".bbc1",\
        "obsolete_timeout": 300\
    },\
    "domains": {\
        "0000000000000000000000000000000000000000000000000000000000000000": {\
            "module": "p2p_domain0",\
            "static_nodes": {},\
            "use_ledger_subsystem": false,\
            "ledger_subsystem": {\
                "subsystem": "ethereum",\
                "max_transactions": 4096,\
                "max_seconds": 3600\
            }\
        }\
    },\
    "ethereum": {\
        "chain_id": 15,\
        "port": 30303,\
        "log": "geth.log",\
        "account": "",\
        "passphrase": "",\
        "contract": "BBcAnchor",\
        "contract_address": ""\
    }\
}'


def parser():
    usage = 'python -t <put|delete> -d <DOMAIN_HEX> -k1 <K1NAME> -v1 <K1VALUE> [-k2 <K2NAME>] [-v2 <K2VALUE>] -w <WORKINGDIR>'
    argparser = ArgumentParser(usage=usage)
    argparser.add_argument('-t', '--type', type=str, choices=['put', 'delete'],
                           default=None, help='operation type', required=True)
    argparser.add_argument('-d', '--domainhex', type=str, default=None, help='domain hex', required=True)
    argparser.add_argument('-k1', '--key1name', type=str, default=None, help='key1 name', required=False)
    argparser.add_argument('-v', '--value', type=str, default=None, help='value', required=True)
    argparser.add_argument('-k2', '--key2name', type=str, default=None, help='key2 name', required=False)
    argparser.add_argument('-w', '--workingdir', type=str, default=DEFAULT_WORKING_DIR, help='working directory', required=False)
    args = argparser.parse_args()

    if not os.path.exists(args.workingdir):
        print("dir not found : %s" % args.workingdir)
        raise ValueError("dir not found")

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
        if (str is None):
            return None
        elif (str.upper() == 'TRUE'):
            return True
        elif (str.upper() == 'FALSE'):
            return False
        else:
            return str


def convertKeyValue(name, value):
    obj = {}
    obj["key"] = name
    obj["value"] = convertValue(value)
    return obj


def getTargetFile(argresult):
    wdir = argresult.workingdir
    filepath = wdir + "/" + DEFAULT_CONFIG_FILE
    print("input filepath : %s" % filepath)
    if os.path.exists(filepath):
        return filepath
    else:
        return None


def getOutputFilepath(argresult):
    wdir = argresult.workingdir
    filepath = wdir + "/" + DEFAULT_CONFIG_FILE
    return filepath


def fetchTargetObj(filepath):
    print("filepath : %s" % filepath)
    if filepath and os.path.exists(filepath):
        with open(filepath, 'r') as f:
            print("load from %s" % filepath)
            targetObj = json.load(f)
    else:
        print("load from default")
        targetObj = json.loads(DEFAULT_JSON)
    return targetObj


def file_output(filepath, targetobj):
    try:
        with open(filepath, "w") as f:
            f.write(json.dumps(targetobj))
    except:
        print("failed file_output : %s" % filepath)
        return False
    return True


def put_proc(targetobj, domainhex, k1obj, k2obj, filepath):
    print(targetobj)
    print("------")
    if k1obj['value'] == None and k2obj['value'] == None:
        print("-v is None")
        return False
    if k2obj['key'] is not None and k1obj['key'] == None:
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
    return file_output(filepath, targetobj)


def delete_proc(targetobj, domainhex, k1obj, k2obj, filepath):
    print(targetobj)
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
    return file_output(filepath, targetobj)


if __name__ == '__main__':
    try:
        argresult = parser()
    except Exception as e:
        print("failed to parse")
        sys.exit(1)

    if argresult.key2name is None:
        k1obj = convertKeyValue(argresult.key1name, argresult.value)
        k2obj = convertKeyValue(None, None)
    else:
        k1obj = convertKeyValue(argresult.key1name, None)
        k2obj = convertKeyValue(argresult.key2name, argresult.value)
    domainhex = argresult.domainhex
    fpath = getTargetFile(argresult)
    outputfpath = getOutputFilepath(argresult)
    targetobj = fetchTargetObj(fpath)

    if argresult.type == 'put':
        ret = put_proc(targetobj, domainhex, k1obj, k2obj, outputfpath)
    elif argresult.type == 'delete':
        ret = delete_proc(targetobj, domainhex, k1obj, k2obj, outputfpath)
    if ret == False:
        print("failed to proc")
        sys.exit(1)

    sys.exit(0)
