# -*- coding: utf-8 -*-
import binascii
import os
import shutil
import threading
import time
import copy

import sys
sys.path.extend(["../"])
from bbc1.core import bbclib
from bbc1.core.message_key_types import KeyType
from bbc1.core import bbc_core, bbc_app
from bbc1.core.bbc_config import DEFAULT_CORE_PORT, DEFAULT_P2P_PORT

cores = None
clients = None
stats = None
common_domain_id = None
loglv = 'debug'
config_file = None


def prepare(core_num=1, client_num=1, conf_file=None, loglevel='debug'):
    global cores, clients, stats, config_file, loglv
    cores = [None for i in range(core_num)]
    stats = [None for i in range(core_num)]
    clients = [dict() for i in range(client_num)]
    loglv = loglevel
    config_file = conf_file


def get_core_client():
    return cores, clients


def start_core_thread(index, core_port_increment=0, p2p_port_increment=0,
                      use_nodekey=False, use_domain0=False, remove_dir=True):
    core_port = DEFAULT_CORE_PORT + core_port_increment
    p2p_port = DEFAULT_P2P_PORT + p2p_port_increment
    th = threading.Thread(target=start_core, args=(index, core_port, p2p_port, use_nodekey, use_domain0, remove_dir,))
    th.setDaemon(True)
    th.start()
    time.sleep(0.1)


def start_core(index, core_port, p2p_port, use_nodekey=False, use_domain0=False, remove_dir=True):
    print("** [%d] start: port=%i" % (index, core_port))
    if remove_dir and os.path.exists(".bbc1-%i/" % core_port):
        shutil.rmtree(".bbc1-%i/" % core_port)
    cores[index] = bbc_core.BBcCoreService(p2p_port=p2p_port, core_port=core_port,
                                           workingdir=".bbc1-%i/" % core_port,
                                           configfile=config_file,
                                           use_nodekey=use_nodekey,
                                           use_domain0=use_domain0,
                                           server_start=False,
                                           loglevel=loglv)
    cores[index].start_server(port=core_port)


def domain_setup_utility(core_port_increment, dom_id, network_module=None):
    cl = bbc_app.BBcAppClient(port=DEFAULT_CORE_PORT + core_port_increment)
    cl.domain_setup(dom_id)
    global common_domain_id
    common_domain_id = dom_id
    wait_check_result_msg_type(cl.callback, bbclib.MsgType.RESPONSE_SETUP_DOMAIN)
    cl.unregister_from_core()


def make_client(index, core_port_increment, callback=None, connect_to_core=True, domain_id=None):
    keypair = bbclib.KeyPair()
    keypair.generate()
    clients[index]['user_id'] = bbclib.get_new_id("user_%i" % index)
    clients[index]['keypair'] = keypair
    if connect_to_core:
        if domain_id is None:
            global common_domain_id
            domain_id = common_domain_id
        clients[index]['app'] = bbc_app.BBcAppClient(port=DEFAULT_CORE_PORT + core_port_increment, loglevel=loglv)
        clients[index]['app'].set_user_id(clients[index]['user_id'])
        clients[index]['app'].set_domain_id(domain_id)
    if callback is not None:
        clients[index]['app'].set_callback(callback)
    print("[%i] user_id = %s" % (index, binascii.b2a_hex(clients[index]['user_id'])))


def get_random_data(length=16):
    import random
    source_str = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
    return "".join([random.choice(source_str) for x in range(length)])


def wait_check_result_msg_type(callback, msg_type):
    dat = callback.synchronize()
    if dat[KeyType.command] != msg_type:
        print("XXXXXX not expected result: %d <=> %d(received)" % (msg_type, dat[KeyType.command]))
    return dat


def get_stats(i):
    global stats
    stats[i] = copy.deepcopy(cores[i].stats.get_stats())


def get_stat_diffs(i):
    stats_diff = copy.deepcopy(cores[i].stats.get_stats())
    for key in stats_diff.keys():
        for key2 in stats_diff[key].keys():
            if key in stats[i]:
                stats_diff[key][key2] -= stats[i][key].get(key2, 0)
    get_stats(i)
    return stats_diff
