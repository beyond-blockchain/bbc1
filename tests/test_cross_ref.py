# -*- coding: utf-8 -*-
import pytest

import pprint
import time

import sys
sys.path.extend(["../"])
from bbc1.common import bbclib
from bbc1.app import bbc_app
from testutils import prepare, get_core_client, start_core_thread, make_client, domain_setup_utility
from bbc1.core import domain0_manager, user_message_routing
from bbc1.common.message_key_types import KeyType


LOGLEVEL = 'info'
#LOGLEVEL = 'debug'

domain_num = 3
core_per_domain = 5
core_num = domain_num * core_per_domain
client_per_core = 2
client_num = core_num * client_per_core
cores = None
clients = None
domain_ids = [bbclib.get_new_id("testdomain%d" % i) for i in range(domain_num)]
asset_group_id = bbclib.get_new_id("asset_group_0")

core_domains = [None for i in range(core_num)]
msg_processor = [None for i in range(client_num)]

num_assign_cross_ref = 0


def show_domain_list(domain_list):
    for dm in domain_list.keys():
        print(" Domain:", dm.hex())
        for nd in domain_list[dm]:
            print("   node_id:", nd.hex())


def sleep_tick(wait_for):
    print("-- sleep %d sec" % wait_for)
    end_time = time.time() + wait_for
    while time.time() < end_time:
        print("(%d) .. waiting" % int(time.time()))
        time.sleep(1)


def prepare_transaction(asset_group, client, datnum, txid_pointer=None):
    user_id = client['user_id']
    kp = client['keypair']
    txobj = bbclib.BBcTransaction()
    rtn = bbclib.BBcRelation()
    asset = bbclib.BBcAsset()
    asset.add(user_id=user_id, asset_body=b'data=%d' % datnum)
    rtn.add(asset_group_id=asset_group, asset=asset)
    if txid_pointer is not None:
        ptr = bbclib.BBcPointer()
        ptr.add(transaction_id=txid_pointer)
        rtn.add(pointer=ptr)
    wit = bbclib.BBcWitness()
    txobj.add(relation=rtn, witness=wit)
    wit.add_witness(user_id)
    client['app'].include_cross_ref(txobj)
    sig = txobj.sign(key_type=bbclib.KeyType.ECDSA_SECP256k1, keypair=kp)
    txobj.add_signature(user_id=user_id, signature=sig)
    txobj.digest()
    return txobj


class TestBBcAppClient(object):

    def test_00_setup(self):
        print("-----", sys._getframe().f_code.co_name, "-----")
        domain0_manager.Domain0Manager.DOMAIN_INFO_ADVERTISE_INTERVAL = 4  # just for testing
        domain0_manager.Domain0Manager.DOMAIN_INFO_LIFETIME = 8  # just for testing
        domain0_manager.Domain0Manager.NUM_OF_COPIES = 1
        user_message_routing.UserMessageRouting.MAX_CROSS_REF_STOCK = 0

        global msg_processor
        prepare(core_num=core_num, client_num=client_num, loglevel=LOGLEVEL)
        for i in range(domain_num):
            for j in range(core_per_domain):
                base_core_index = i * core_per_domain + j
                domain0_flag = True if j == 0 else False
                start_core_thread(index=base_core_index, core_port_increment=base_core_index,
                                  p2p_port_increment=base_core_index, use_domain0=domain0_flag)
                domain_setup_utility(base_core_index, domain_ids[i])
                core_domains[base_core_index] = domain_ids[i]
        time.sleep(1)
        for i in range(domain_num):
            print("domain:", i)
            for j in range(core_per_domain):
                base_core_index = i * core_per_domain + j
                print(" base_core_index:", base_core_index)
                print("  client_index:", base_core_index*client_per_core, base_core_index*client_per_core+1)
                for k in range(client_per_core):
                    make_client(index=base_core_index*client_per_core+k, core_port_increment=base_core_index,
                                domain_id=domain_ids[i])
        time.sleep(1)

        global cores, clients
        cores, clients = get_core_client()
        for i in range(client_num):
            msg_processor[i] = clients[i]['app'].callback

    def test_1_register(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        for cl in clients:
            ret = cl['app'].register_to_core()
            assert ret
        time.sleep(1)

    def test_2_setup_network_domain0(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        ipv4 = cores[0].networking.ip_address
        ipv6 = cores[0].networking.ip6_address
        port = cores[0].networking.port
        for i in [5, 10]:
            cores[i].networking.send_domain_ping(domain_id=bbclib.domain_global_0, ipv4=ipv4, ipv6=ipv6, port=port, is_static=True)
        print("-- wait 5 seconds --")
        time.sleep(5)

        assert len(cores[0].networking.domains[bbclib.domain_global_0]['neighbor'].nodeinfo_list) == domain_num - 1
        assert len(cores[5].networking.domains[bbclib.domain_global_0]['neighbor'].nodeinfo_list) == domain_num - 1
        assert len(cores[10].networking.domains[bbclib.domain_global_0]['neighbor'].nodeinfo_list) == domain_num - 1
        assert bbclib.domain_global_0 not in cores[1].networking.domains
        print("-- wait 5 seconds --")
        time.sleep(5)

    def test_3_setup_network(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        for i in range(domain_num):
            base_client_index = i*core_per_domain*client_per_core
            #print("base_client_index:", base_client_index)
            clients[base_client_index]['app'].get_domain_neighborlist(domain_id=domain_ids[i])
            dat = msg_processor[base_client_index].synchronize()
            print("[%d] nodeinfo = %s" % (i * core_per_domain, dat[0]))
            node_id, ipv4, ipv6, port, domain0 = dat[0]
            for j in range(core_per_domain):
                c_index = base_client_index + j * client_per_core
                clients[c_index]['app'].send_domain_ping(domain_ids[i], ipv4, ipv6, port)
        print("*** wait 5 seconds ***")
        time.sleep(5)

        for i in range(domain_num):
            print("**** domain:%d" % i)
            print(cores[i*core_per_domain].networking.domains[domain_ids[i]]['neighbor'].show_list())
            print(cores[i*core_per_domain+1].networking.domains[domain_ids[i]]['neighbor'].show_list())
            print(cores[i*core_per_domain+2].networking.domains[domain_ids[i]]['neighbor'].show_list())

    def test_13_wait(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        print("-- sleep 10 sec")
        time.sleep(10)
        for i in range(domain_num):
            print("****** [%d] %s ******" % (i, cores[i*core_per_domain].networking.domain0manager.my_node_id.hex()))
            dm = cores[i*core_per_domain].networking.domain0manager.domain_list
            show_domain_list(dm)
        print("-- sleep 10 sec")
        time.sleep(10)
        for i in range(domain_num):
            nd = cores[i*core_per_domain].networking.domain0manager.node_domain_list
            assert len(nd) == 2

    def test_20_make_transactions(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        i = 0
        for k, cl in enumerate(clients):
            if k % 5 == 0:
                continue
            for j in range(5):
                txobj = prepare_transaction(asset_group_id, cl, i)
                cl['app'].insert_transaction(txobj)
                i += 1
        time.sleep(3)

        global num_assign_cross_ref
        num_cross_ref_in_clients = 0
        for i, cl in enumerate(clients):
            num_cross_ref_in_clients += len(cl['app'].cross_ref_list)
            if len(cl['app'].cross_ref_list) > 1:
                print("over:", len(cl['app'].cross_ref_list)-1)
            cl['app'].get_stats()
            dat = msg_processor[i].synchronize()
            if KeyType.stats in dat and b'domain0' in dat[KeyType.stats]:
                stat = dat[KeyType.stats]
                print("[%d] distribute_cross_ref_in_domain0=%d" % (i, stat[b'domain0'][b'distribute_cross_ref_in_domain0']))
                print("[%d] GET_CROSS_REF_DISTRIBUTION=%d" % (i, stat[b'domain0'][b'GET_CROSS_REF_DISTRIBUTION']))
                print("[%d] assign_cross_ref_to_nodes=%d" % (i, stat[b'domain0'][b'assign_cross_ref_to_nodes']))
                if b'drop_cross_ref_because_exceed_margin' in stat[b'domain0']:
                    print("[%d] drop_cross_ref_because_exceed_margin=%d" % (i, stat[b'domain0'][b'drop_cross_ref_because_exceed_margin']))
                num_assign_cross_ref += stat[b'domain0'][b'assign_cross_ref_to_nodes']
        assert num_cross_ref_in_clients == num_assign_cross_ref

    def test_21_make_transactions(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        i = 100
        num_including_cross_ref = 0
        for k, cl in enumerate(clients):
            if k % 5 == 0:
                continue
            for j in range(5):
                txobj = prepare_transaction(asset_group_id, cl, i)
                cl['app'].insert_transaction(txobj)
                if len(txobj.cross_refs) > 0:
                    num_including_cross_ref += 1
                i += 1
        time.sleep(5)

        num_cross_ref_in_clients = 0
        for i, cl in enumerate(clients):
            num_cross_ref_in_clients += len(cl['app'].cross_ref_list)

        num_cross_ref_registered = 0
        for i, cl in enumerate(clients):
            cl['app'].get_stats()
            dat = msg_processor[i].synchronize()
            if KeyType.stats in dat and b'domain0' in dat[KeyType.stats]:
                stat = dat[KeyType.stats]
                print("[%d] cross_ref_registered=%d" % (i, stat[b'domain0'][b'cross_ref_registered']))
                num_cross_ref_registered += stat[b'domain0'][b'cross_ref_registered']
        assert num_including_cross_ref == num_cross_ref_registered


if __name__ == '__main__':
    pytest.main()
