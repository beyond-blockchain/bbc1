# -*- coding: utf-8 -*-
import pytest
import sys
import json
import os
import shutil
sys.path.extend(["../"])
from bbc1.core.bbc_config import DEFAULT_WORKING_DIR, DEFAULT_CONFIG_FILE

from utils.bbc_domain_config import convertKeyValue, put_proc, delete_proc, fetchTargetObj, getTargetFile


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



class TestBBcDomainConfig(object):
    # 正常系
    # 正常系 : convertKeyValue（valueは文字列）のテスト
    def test_00_valid(self):
        print("-----", sys._getframe().f_code.co_name, "-----")
        obj = convertKeyValue("key1", "value1")
        assert obj["key"] == "key1"
        assert obj["value"] == "value1"

    # 正常系 : convertKeyValue（valueは数値）のテスト
    def test_01_valid(self):
        print("-----", sys._getframe().f_code.co_name, "-----")
        obj = convertKeyValue("key1", "100")
        assert obj["key"] == "key1"
        assert obj["value"] == 100

    # 正常系 : convertKeyValue（valueはboolean）のテスト
    def test_02_valid(self):
        print("-----", sys._getframe().f_code.co_name, "-----")
        obj = convertKeyValue("key1", "True")
        assert obj["key"] == "key1"
        assert obj["value"] == True

    # 正常系 : convertKeyValue（valueはjson）のテスト
    def test_03_valid(self):
        print("-----", sys._getframe().f_code.co_name, "-----")
        obj = convertKeyValue("key1", '{"k2": "v2"}')
        assert obj["key"] == "key1"
        assert obj["value"]["k2"] == "v2"

    # 正常系 : put(add), domainhex, k1, v1
    def test_04_valid(self):
        print("-----", sys._getframe().f_code.co_name, "-----")
        targetobj = json.loads(DEFAULT_JSON)
        domainhex = "0000000000000000000000000000000000000000000000000000000000000000"
        k1obj = {"key": "testkey1", "value": "testval1"}
        k2obj = {"key": None, "value": None}
        fpath = "test04output.json"
        put_proc(targetobj, domainhex, k1obj, k2obj, fpath)
        with open(fpath, "r") as f:
            loadobj = json.load(f)
        assert loadobj["domains"][domainhex][k1obj['key']] == k1obj["value"]
        os.remove(fpath)

    # 正常系 : put(update), domainhex, k1, v1
    def test_05_valid(self):
        print("-----", sys._getframe().f_code.co_name, "-----")
        targetobj = json.loads(DEFAULT_JSON)
        domainhex = "0000000000000000000000000000000000000000000000000000000000000000"
        k1obj = {"key": "use_ledger_subsystem", "value": False}
        k2obj = {"key": None, "value": None}
        fpath = "test05output.json"
        put_proc(targetobj, domainhex, k1obj, k2obj, fpath)
        with open(fpath, "r") as f:
            loadobj = json.load(f)
        assert loadobj["domains"][domainhex][k1obj['key']] == k1obj["value"]
        os.remove(fpath)

    # 正常系 : put(add), domainhex, k1, v1, k2, v2
    def test_06_valid(self):
        print("-----", sys._getframe().f_code.co_name, "-----")
        targetobj = json.loads(DEFAULT_JSON)
        domainhex = "0000000000000000000000000000000000000000000000000000000000000000"
        k1obj = {"key": "ledger_subsystem", "value": False}
        k2obj = {"key": "key2", "value": "value2"}
        fpath = "test06output.json"
        put_proc(targetobj, domainhex, k1obj, k2obj, fpath)
        with open(fpath, "r") as f:
            loadobj = json.load(f)
        assert loadobj["domains"][domainhex][k1obj['key']][k2obj['key']] == k2obj["value"]
        os.remove(fpath)

    # 正常系 : put(update), domainhex, k1, v1, k2, v2
    def test_07_valid(self):
        print("-----", sys._getframe().f_code.co_name, "-----")
        targetobj = json.loads(DEFAULT_JSON)
        domainhex = "0000000000000000000000000000000000000000000000000000000000000000"
        k1obj = {"key": "ledger_subsystem", "value": False}
        k2obj = {"key": "max_seconds", "value": 7200}
        fpath = "test07output.json"
        put_proc(targetobj, domainhex, k1obj, k2obj, fpath)
        with open(fpath, "r") as f:
            loadobj = json.load(f)
        assert loadobj["domains"][domainhex][k1obj['key']][k2obj['key']] == k2obj["value"]
        os.remove(fpath)

    # 正常系 : delete, domainhex, k1
    def test_08_valid(self):
        print("-----", sys._getframe().f_code.co_name, "-----")
        targetobj = json.loads(DEFAULT_JSON)
        domainhex = "0000000000000000000000000000000000000000000000000000000000000000"
        k1obj = {"key": "use_ledger_subsystem", "value": False}
        k2obj = {"key": None, "value": None}
        fpath = "test08output.json"
        delete_proc(targetobj, domainhex, k1obj, k2obj, fpath)
        with open(fpath, "r") as f:
            loadobj = json.load(f)
        assert k1obj['key'] not in loadobj["domains"][domainhex]
        os.remove(fpath)

    # 正常系 : delete, domainhex, k1, k2
    def test_09_valid(self):
        print("-----", sys._getframe().f_code.co_name, "-----")
        targetobj = json.loads(DEFAULT_JSON)
        domainhex = "0000000000000000000000000000000000000000000000000000000000000000"
        k1obj = {"key": "ledger_subsystem", "value": False}
        k2obj = {"key": "max_seconds", "value": 600}
        fpath = "test09output.json"
        delete_proc(targetobj, domainhex, k1obj, k2obj, fpath)
        with open(fpath, "r") as f:
            loadobj = json.load(f)
        assert k2obj['key'] not in loadobj["domains"][domainhex][k1obj['key']]
        os.remove(fpath)

    # 正常系 : fileinput 指定ファイルからのjson読み込み
    def test_10_valid(self):
        print("-----", sys._getframe().f_code.co_name, "-----")
        targetobj = json.loads(DEFAULT_JSON)
        domainhex = "0000000000000000000000000000000000000000000000000000000000000000"
        k1obj = {"key": "ledger_subsystem", "value": False}
        k2obj = {"key": "max_seconds", "value": 600}
        fpath = "sample_config.json"
        loadobj = fetchTargetObj(fpath)
        assert domainhex in loadobj["domains"]

    # 正常系 : fileinput デフォルト文字列からのjson読み込み
    def test_11_valid(self):
        print("-----", sys._getframe().f_code.co_name, "-----")
        targetobj = json.loads(DEFAULT_JSON)
        domainhex = "0000000000000000000000000000000000000000000000000000000000000000"
        k1obj = {"key": "ledger_subsystem", "value": False}
        k2obj = {"key": "max_seconds", "value": 600}
        fpath = None
        loadobj = fetchTargetObj(fpath)
        assert domainhex in loadobj["domains"]

    # 正常系 : fileoutput 指定ディレクトリあり, config.jsonファイルあり（上書き）
    def test_12_valid(self):
        os.mkdir('sample_config')
        shutil.copy('sample_config.json', 'sample_config/sample_config.json')
        fpath = "sample_config/sample_config.json"
        print("-----", sys._getframe().f_code.co_name, "-----")
        with open(fpath, "r") as f:
            targetobj = json.load(f)
        domainhex = "0000000000000000000000000000000000000000000000000000000000000000"
        k1obj = {"key": "use_ledger_subsystem", "value": False}
        k2obj = {"key": None, "value": None}
        outfpath = "sample_config/sample_config.json"
        ret = put_proc(targetobj, domainhex, k1obj, k2obj, outfpath)
        assert ret == True
        with open(outfpath, "r") as f:
            loadobj = json.load(f)
        assert loadobj["domains"][domainhex][k1obj['key']] == k1obj["value"]
        os.remove('sample_config/sample_config.json')
        os.rmdir('sample_config')

    # 異常系 :
    # 異常系 : put(add), domainhex (not exist), k1, v1, k2, v2
    def test_51_invalid(self):
        print("-----", sys._getframe().f_code.co_name, "-----")
        targetobj = json.loads(DEFAULT_JSON)
        domainhex = "0000000000000000000000000000000000000000000000000000000000000001"
        k1obj = {"key": "ledger_subsystem", "value": False}
        k2obj = {"key": "max_seconds", "value": 7200}
        fpath = "test51output.json"
        ret = put_proc(targetobj, domainhex, k1obj, k2obj, fpath)
        assert ret == False

    # 異常系 : domainhexを指定しない場合
    def test_52_invalid(self):
        print("-----", sys._getframe().f_code.co_name, "-----")
        targetobj = json.loads(DEFAULT_JSON)
        domainhex = None
        k1obj = {"key": "ledger_subsystem", "value": False}
        k2obj = {"key": "max_seconds", "value": 7200}
        fpath = "test52output.json"
        ret = put_proc(targetobj, domainhex, k1obj, k2obj, fpath)
        assert ret == False

    # 異常系 : putでdomainhex, k1のみ指定した場合（v1がない）
    def test_53_invalid(self):
        print("-----", sys._getframe().f_code.co_name, "-----")
        targetobj = json.loads(DEFAULT_JSON)
        domainhex = "0000000000000000000000000000000000000000000000000000000000000000"
        k1obj = {"key": "use_ledger_subsystem", "value": None}
        k2obj = {"key": None, "value": None}
        fpath = "test53output.json"
        ret = put_proc(targetobj, domainhex, k1obj, k2obj, fpath)
        assert ret == False

    # 異常系 : putでdomainhex, k1, k2のみ指定した場合（v2がない）
    def test_54_invalid(self):
        print("-----", sys._getframe().f_code.co_name, "-----")
        targetobj = json.loads(DEFAULT_JSON)
        domainhex = "0000000000000000000000000000000000000000000000000000000000000000"
        k1obj = {"key": "ledger_subsystem", "value": None}
        k2obj = {"key": 'subsystem', "value": None}
        fpath = "test54output.json"
        ret = put_proc(targetobj, domainhex, k1obj, k2obj, fpath)
        assert ret == False

    # 異常系 : putでdomainhex, k2. v2を指定した場合（k1, v2がない）
    def test_55_invalid(self):
        print("-----", sys._getframe().f_code.co_name, "-----")
        targetobj = json.loads(DEFAULT_JSON)
        domainhex = "0000000000000000000000000000000000000000000000000000000000000000"
        k1obj = {"key": None, "value": None}
        k2obj = {"key": 'subsystem', "value": "ethereum2"}
        fpath = "test55output.json"
        ret = put_proc(targetobj, domainhex, k1obj, k2obj, fpath)
        assert ret == False

    # 異常系 : deleteで存在しないk1を指定した場合
    def test_56_invalid(self):
        print("-----", sys._getframe().f_code.co_name, "-----")
        targetobj = json.loads(DEFAULT_JSON)
        domainhex = "0000000000000000000000000000000000000000000000000000000000000000"
        k1obj = {"key": "use_ledger_subsystem_invalid", "value": False}
        k2obj = {"key": None, "value": None}
        fpath = "test56output.json"
        ret = delete_proc(targetobj, domainhex, k1obj, k2obj, fpath)
        assert ret == False

    # 異常系 : deleteで存在しないk2を指定した場合
    def test_57_valid(self):
        print("-----", sys._getframe().f_code.co_name, "-----")
        targetobj = json.loads(DEFAULT_JSON)
        domainhex = "0000000000000000000000000000000000000000000000000000000000000000"
        k1obj = {"key": "ledger_subsystem", "value": False}
        k2obj = {"key": "max_seconds_invalid", "value": 600}
        fpath = "test57output.json"
        ret = delete_proc(targetobj, domainhex, k1obj, k2obj, fpath)
        assert ret == False

    # 異常系 : fileoutput 指定ディレクトリあり（存在しないディレクトリ）
    def test_58_valid(self):
        os.mkdir('sample_config')
        shutil.copy('sample_config.json', 'sample_config/sample_config.json')
        fpath = "sample_config/sample_config.json"
        print("-----", sys._getframe().f_code.co_name, "-----")
        with open(fpath, "r") as f:
            targetobj = json.load(f)
        domainhex = "0000000000000000000000000000000000000000000000000000000000000000"
        k1obj = {"key": "use_ledger_subsystem", "value": False}
        k2obj = {"key": None, "value": None}
        outfpath = "sample_config2/sample_config.json"
        ret = put_proc(targetobj, domainhex, k1obj, k2obj, outfpath)
        assert ret == False
        os.remove('sample_config/sample_config.json')

