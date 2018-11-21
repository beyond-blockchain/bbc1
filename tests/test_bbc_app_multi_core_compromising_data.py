
import pytest

import os
import binascii
import time
import random

import sys
sys.path.extend(["../"])
from bbc1.core import bbclib
from bbc1.core.message_key_types import KeyType
from bbc1.core import bbc_app
from testutils import prepare, get_core_client, start_core_thread, make_client, domain_setup_utility


LOGLEVEL = 'debug'
LOGLEVEL = 'none'


core_num = 5
client_num = 5
cores = None
clients = None
domain_id = bbclib.get_new_id("testdomain")
asset_group_id = bbclib.get_new_id("asset_group_1")
transactions = list()
msg_processor = [None for i in range(client_num)]

asset_file_content = b"AAAAAAAAAAAAAAAAAAAAAAAAA"

asset_id_0 = None


def make_transaction(user_id, keypair):
    txobj = bbclib.make_transaction(relation_num=1, witness=True)
    bbclib.add_relation_asset(txobj, relation_idx=0, asset_group_id=asset_group_id, user_id=user_id,
                              asset_body="data=%d" % random.randint(1, 10000),
                              asset_file=asset_file_content)
    txobj.witness.add_witness(user_id)
    sig = txobj.sign(keypair=keypair)
    txobj.add_signature(user_id, sig)
    txobj.digest()
    return txobj


class MessageProcessor(bbc_app.Callback):
    def __init__(self, index=0):
        super(MessageProcessor, self).__init__(self)
        self.idx = index


class TestBBcAppClient(object):

    def test_00_setup(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        print("domain_id =", binascii.b2a_hex(domain_id))

        global msg_processor
        prepare(core_num=core_num, client_num=client_num, loglevel=LOGLEVEL)
        for i in range(core_num):
            start_core_thread(index=i, core_port_increment=i, p2p_port_increment=i)
            domain_setup_utility(i, domain_id)  # system administrator
        time.sleep(1)
        for i in range(client_num):
            msg_processor[i] = MessageProcessor(index=i)
            make_client(index=i, core_port_increment=i, callback=msg_processor[i])
        time.sleep(1)

        global cores, clients
        cores, clients = get_core_client()

    def test_10_setup_network(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        ret = clients[0]['app'].get_domain_neighborlist(domain_id=domain_id)
        assert ret
        dat = msg_processor[0].synchronize()
        print("[0] nodeinfo=", dat[0])
        node_id, ipv4, ipv6, port, domain0 = dat[0]

        for i in range(1, client_num):
            clients[i]['app'].send_domain_ping(domain_id, ipv4, ipv6, port)
        print("*** wait 15 seconds ***")
        time.sleep(15)

        for i in range(core_num):
            print(cores[i].networking.domains[domain_id]['neighbor'].show_list())
            assert len(cores[i].networking.domains[domain_id]['neighbor'].nodeinfo_list) == core_num - 1

    def test_11_register(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        for cl in clients:
            ret = cl['app'].register_to_core()
            assert ret
        time.sleep(1)

    def test_12_make_transaction(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        global transactions
        for i, cl in enumerate(clients):
            user_id = cl['user_id']
            keypair = cl['keypair']
            transaction = make_transaction(user_id, keypair)
            print("register transaction=", binascii.b2a_hex(transaction.transaction_id))
            cl['app'].insert_transaction(transaction)
            dat = msg_processor[i].synchronize()
            assert KeyType.transaction_id in dat
            assert dat[KeyType.transaction_id] == transaction.transaction_id
            transactions.append(transaction)
            if i == 0:
                global asset_id_0
                asset_id_0 = transaction.relations[0].asset.asset_id
        time.sleep(2)

    def test_13_search_transaction(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        print("find txid=", binascii.b2a_hex(transactions[0].transaction_id))
        clients[0]['app'].search_transaction(transactions[0].transaction_id)
        dat = msg_processor[0].synchronize()
        assert dat[KeyType.status] == 0
        #assert len(dat[KeyType.compromised_transaction_data]) > 0
        txobj, fmt_type = bbclib.deserialize(dat[KeyType.transaction_data])
        print(txobj)

        print("find txid=", binascii.b2a_hex(transactions[1].transaction_id))
        clients[1]['app'].search_transaction(transactions[1].transaction_id)
        dat = msg_processor[1].synchronize()
        assert dat[KeyType.status] == 0
        #assert len(dat[KeyType.compromised_transaction_data]) > 0
        txobj, fmt_type = bbclib.deserialize(dat[KeyType.transaction_data])
        print(txobj)

    def test_14_forge_transaction(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")

        print("* forge transaction[0] and update the data in node 0")
        txobj = transactions[0]
        txdata = bytearray(bbclib.serialize(txobj))
        txdata[int(len(txdata)/3)] = txdata[int(len(txdata)/3)] + 0x01
        data_handler = cores[0].networking.domains[domain_id]['data']
        sql = "UPDATE transaction_table SET transaction_data = %s WHERE transaction_id = %s" % \
              (data_handler.db_adaptors[0].placeholder, data_handler.db_adaptors[0].placeholder)
        data_handler.exec_sql(sql=sql, args=(bytes(txdata), txobj.transaction_id), commit=True)

        print("* forge transaction[1] with the data of transaction[2] and update the data in node 1")
        txobj = transactions[1]
        txdata = bbclib.serialize(transactions[2])
        data_handler = cores[1].networking.domains[domain_id]['data']
        sql = "UPDATE transaction_table SET transaction_data = %s WHERE transaction_id = %s" % \
              (data_handler.db_adaptors[0].placeholder, data_handler.db_adaptors[0].placeholder)
        data_handler.exec_sql(sql=sql, args=(bytes(txdata), txobj.transaction_id), commit=True)

    def test_15_search_transaction(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        print("find txid=", binascii.b2a_hex(transactions[0].transaction_id))
        clients[0]['app'].search_transaction(transactions[0].transaction_id)
        dat = msg_processor[0].synchronize()
        assert dat[KeyType.status] < 0
        assert len(dat[KeyType.compromised_transaction_data]) > 0

        print("find txid=", binascii.b2a_hex(transactions[1].transaction_id))
        clients[1]['app'].search_transaction(transactions[1].transaction_id)
        dat = msg_processor[1].synchronize()
        assert dat[KeyType.status] < 0
        assert len(dat[KeyType.compromised_transaction_data]) > 0

    def test_16_send_repair_request(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        clients[0]['app'].request_to_repair_transaction(transactions[0].transaction_id)
        clients[1]['app'].request_to_repair_transaction(transactions[1].transaction_id)
        print("--- wait 5 seconds ---")
        time.sleep(5)

    def test_17_search_transaction(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        print("find txid=", binascii.b2a_hex(transactions[0].transaction_id))
        clients[0]['app'].search_transaction(transactions[0].transaction_id)
        dat = msg_processor[0].synchronize()
        assert dat[KeyType.status] == 0
        assert KeyType.compromised_transaction_data not in dat
        assert KeyType.transaction_data in dat
        print(bbclib.deserialize(dat[KeyType.transaction_data]))

        print("find txid=", binascii.b2a_hex(transactions[1].transaction_id))
        clients[1]['app'].search_transaction(transactions[1].transaction_id)
        dat = msg_processor[1].synchronize()
        assert dat[KeyType.status] == 0
        assert KeyType.compromised_transaction_data not in dat
        assert KeyType.transaction_data in dat

    def test_20_forge_asset_file(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        path = os.path.join(".bbc1-9000", domain_id.hex(), asset_group_id.hex(), asset_id_0.hex())
        with open(path, "a") as f:
            f.write("XXXX")
        with open(path, "r") as f:
            print(f.read())

    def test_21_search_transaction(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        print("find txid=", binascii.b2a_hex(transactions[0].transaction_id))
        clients[0]['app'].search_transaction(transactions[0].transaction_id)
        dat = msg_processor[0].synchronize()
        assert dat[KeyType.status] < 0
        assert len(dat[KeyType.compromised_asset_files]) > 0
        print("asset file is compromised")

    def test_22_send_repair_request(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        clients[0]['app'].request_to_repair_asset(asset_group_id=asset_group_id, asset_id=asset_id_0)
        print("--- wait 3 seconds ---")
        time.sleep(3)

    def test_23_search_transaction(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        print("find txid=", binascii.b2a_hex(transactions[0].transaction_id))
        clients[0]['app'].search_transaction(transactions[0].transaction_id)
        dat = msg_processor[0].synchronize()
        assert dat[KeyType.status] == 0
        assert KeyType.compromised_asset_files not in dat

    @pytest.mark.unregister
    def test_98_unregister(self):
        for cl in clients:
            ret = cl['app'].unregister_from_core()
            assert ret


if __name__ == '__main__':
    pytest.main()
