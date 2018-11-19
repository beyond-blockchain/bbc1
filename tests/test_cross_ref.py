# -*- coding: utf-8 -*-
import pytest

import random
import time

import sys
sys.path.extend(["../"])
from bbc1.core import bbclib
from testutils import prepare, get_core_client, start_core_thread, make_client, domain_setup_utility
from bbc1.core import domain0_manager, user_message_routing
from bbc1.core.message_key_types import KeyType


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

num_assigned_cross_ref = 0
num_cross_ref_registered = 0
cross_ref_regsistered_list = dict()


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


def prepare_transaction(asset_group, client, datnum, txid_pointer=None, no_cross_ref=False):
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
    if not no_cross_ref:
        client['app'].include_cross_ref(txobj)
    sig = txobj.sign(keypair=kp)
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
        ready_flag = False
        count = 10
        while count > 0 and not ready_flag:
            print("-- sleep 5 sec")
            time.sleep(5)
            ready_flag = True
            for i in range(domain_num):
                for k in range(core_per_domain):
                    idx = i * core_per_domain + k
                    dm = clients[idx*client_per_core]['app'].domain_id
                    print(cores[idx].networking.domains[dm]['neighbor'].show_list())
                    num = len(list(filter(lambda nd: nd.is_domain0_node,
                                          cores[idx].networking.domains[dm]['neighbor'].nodeinfo_list.values())))
                    if k == 0:
                        assert num == 0
                    else:
                        ready_flag = ready_flag & (num == 1)
            count -= 1

    def test_20_make_transactions(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        i = 0
        for k, cl in enumerate(clients):
            if k % 10 <= 1:
                continue
            for j in range(5):
                txobj = prepare_transaction(asset_group_id, cl, i, no_cross_ref=True)
                cl['app'].insert_transaction(txobj)
                msg_processor[k].synchronize()
                i += 1
        time.sleep(3)

        global num_assigned_cross_ref
        num_cross_ref_in_clients = 0
        num_distribute_cross_ref_in_domain0 = 0
        num_drop_cross_ref = 0
        for i, cl in enumerate(clients):
            num_cross_ref_in_clients += len(cl['app'].cross_ref_list)
            if i % 2 == 1:
                continue
            cl['app'].get_stats()
            dat = msg_processor[i].synchronize()
            if KeyType.stats in dat:
                stat = dat[KeyType.stats]
                if i % 10 > 1:
                    #print("[%d] transaction.insert_count=%d" % (i, stat[b'transaction'][b'insert_count']))
                    #print("[%d] data_handler.insert_transaction=%d" % (i, stat[b'data_handler'][b'insert_transaction']))
                    assert stat[b'transaction'][b'insert_count'] == 5 * client_per_core
                    assert stat[b'data_handler'][b'insert_transaction'] == 5 * (core_per_domain - 1) * client_per_core
            if KeyType.stats in dat and b'domain0' in dat[KeyType.stats]:
                if b'domain0' in dat[KeyType.stats]:
                    print("[%d] distribute_cross_ref_in_domain0=%d" %
                          (i, stat[b'domain0'].get(b'distribute_cross_ref_in_domain0', 0)))
                    print("[%d] GET_CROSS_REF_DISTRIBUTION=%d" %
                          (i, stat[b'domain0'].get(b'GET_CROSS_REF_DISTRIBUTION', 0)))
                    print("[%d] assign_cross_ref_to_nodes=%d" %
                          (i, stat[b'domain0'].get(b'assign_cross_ref_to_nodes', 0)))
                    print("[%d] drop_cross_ref_because_exceed_margin=%d" %
                          (i, stat[b'domain0'].get(b'drop_cross_ref_because_exceed_margin', 0)))
                    print("[%d] cross_ref_registered=%d" %
                          (i, stat[b'domain0'].get(b'cross_ref_registered', 0)))
                    num_distribute_cross_ref_in_domain0 += stat[b'domain0'].get(b'distribute_cross_ref_in_domain0', 0)
                    num_assigned_cross_ref += stat[b'domain0'].get(b'assign_cross_ref_to_nodes', 0)
                    num_drop_cross_ref += stat[b'domain0'].get(b'drop_cross_ref_because_exceed_margin', 0)
                    assert stat[b'domain0'].get(b'cross_ref_registered', 0) == 0
        assert num_distribute_cross_ref_in_domain0 == num_assigned_cross_ref + num_drop_cross_ref

    def test_21_make_transactions(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        i = 100
        num_including_cross_ref = 0
        for k, cl in enumerate(clients):
            if k % 10 <= 1:
                continue
            for j in range(5):
                txobj = prepare_transaction(asset_group_id, cl, i)
                cl['app'].insert_transaction(txobj)
                msg_processor[k].synchronize()
                if txobj.cross_ref is not None:
                    num_including_cross_ref += 1
                i += 1
        print("# num_including_cross_ref=", num_including_cross_ref)
        time.sleep(5)

        global num_cross_ref_registered
        for i, cl in enumerate(clients):
            if i % 2 == 1:
                continue
            cl['app'].get_stats()
            dat = msg_processor[i].synchronize()
            if KeyType.stats in dat and b'domain0' in dat[KeyType.stats]:
                stat = dat[KeyType.stats]
                if b'cross_ref_registered' in stat[b'domain0']:
                    print("[%d] cross_ref_registered=%d" % (i, stat[b'domain0'][b'cross_ref_registered']))
                    num_cross_ref_registered += stat[b'domain0'][b'cross_ref_registered']
        assert num_including_cross_ref == num_cross_ref_registered

    def test_22_get_cross_ref_list(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        num_in_registered_list = 0
        global cross_ref_regsistered_list
        for i in [3, 13, 23]:
            clients[i]['app'].request_cross_ref_holders_list()
            dat = msg_processor[i].synchronize()
            assert KeyType.transaction_id_list in dat
            dm = clients[i]['app'].domain_id
            num_in_registered_list += len(dat[KeyType.transaction_id_list])
            cross_ref_regsistered_list.setdefault(dm, list())
            print("----")
            for txid in dat[KeyType.transaction_id_list]:
                print("txid:", txid.hex())
                cross_ref_regsistered_list[dm].append(txid)
        assert num_in_registered_list == num_cross_ref_registered

    def test_23_verify_cross_ref(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        for i in [5, 15, 25]:
            dm = clients[i]['app'].domain_id
            if len(cross_ref_regsistered_list[dm]) == 0:
                continue
            txid_to_verify = random.choice(cross_ref_regsistered_list[dm])
            clients[i]['app'].request_verify_by_cross_ref(txid_to_verify)
            dat = msg_processor[i].synchronize()
            assert KeyType.cross_ref_verification_info in dat
            transaction_base_digest, cross_ref_data, sigdata = dat[KeyType.cross_ref_verification_info]
            assert bbclib.verify_using_cross_ref(dm, txid_to_verify, transaction_base_digest, cross_ref_data, sigdata)


if __name__ == '__main__':
    pytest.main()
