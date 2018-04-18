# -*- coding: utf-8 -*-
import pytest
import sys
import time

sys.path.extend(["../"])
from bbc1.app import id_lib
from bbc1.core import bbc_app
from bbc1.core import bbclib
from bbc1.core.bbc_config import DEFAULT_CORE_PORT


@pytest.fixture()
def default_domain_id():
    domain_id = bbclib.get_new_id("test_id_lib", include_timestamp=False)

    tmpclient = bbc_app.BBcAppClient(port=DEFAULT_CORE_PORT, multiq=False, loglevel="all")
    tmpclient.domain_setup(domain_id, "simple_cluster")
    tmpclient.callback.synchronize()
    tmpclient.unregister_from_core()
    return domain_id


def test_default_map_creation(default_domain_id):

    NUM_KEYPAIRS = 5

    idPubkeyMap = id_lib.BBcIdPublickeyMap(default_domain_id)
    (user_id, keypairs) = idPubkeyMap.create_user_id(num_pubkeys=NUM_KEYPAIRS)

    assert len(keypairs) == NUM_KEYPAIRS

    for i in range(NUM_KEYPAIRS):
        assert idPubkeyMap.is_mapped(user_id, keypairs[i].public_key) == True


def test_map_update(default_domain_id):

    idPubkeyMap = id_lib.BBcIdPublickeyMap(default_domain_id)
    (user_id, keypairs) = idPubkeyMap.create_user_id(num_pubkeys=1)

    assert len(keypairs) == 1

    assert idPubkeyMap.is_mapped(user_id, keypairs[0].public_key) == True

    public_keys = []
    for i in range(3):
        keypair = bbclib.KeyPair()
        public_keys.append(keypair.public_key)

    tx = idPubkeyMap.update(user_id, public_keys_to_replace=public_keys,
            keypair=keypairs[0])

    assert idPubkeyMap.is_mapped(user_id, keypairs[0].public_key) == False
    for i in range(3):
        assert idPubkeyMap.is_mapped(user_id, public_keys[i]) == True


def test_get_map(default_domain_id):

    NUM_KEYPAIRS = 3

    idPubkeyMap = id_lib.BBcIdPublickeyMap(default_domain_id)
    (user_id, keypairs) = idPubkeyMap.create_user_id(num_pubkeys=NUM_KEYPAIRS)

    assert len(keypairs) == NUM_KEYPAIRS

    public_keys = idPubkeyMap.get_mapped_public_keys(user_id)

    assert len(public_keys) == NUM_KEYPAIRS

    for i in range(NUM_KEYPAIRS):
        assert bytes(keypairs[i].public_key) == public_keys[i]


def test_map_creation_with_pubkeys(default_domain_id):

    NUM_KEYPAIRS = 3

    public_keys = []
    for i in range(NUM_KEYPAIRS):
        keypair = bbclib.KeyPair()
        public_keys.append(keypair.public_key)

    idPubkeyMap = id_lib.BBcIdPublickeyMap(default_domain_id)
    (user_id, keypairs) = idPubkeyMap.create_user_id(public_keys=public_keys)

    assert len(keypairs) == 0

    for i in range(NUM_KEYPAIRS):
        assert idPubkeyMap.is_mapped(user_id, public_keys[i]) == True


def test_map_eval(default_domain_id):

    idPubkeyMap = id_lib.BBcIdPublickeyMap(default_domain_id)
    (user_id, keypairs0) = idPubkeyMap.create_user_id()

    time0 = int(time.time())
    print("\n2-second interval.")
    time.sleep(2)

    keypairs1 = []
    public_keys = []
    for i in range(3):
        keypairs1.append(bbclib.KeyPair())
        public_keys.append(keypairs1[i].public_key)

    tx = idPubkeyMap.update(user_id, public_keys_to_add=public_keys,
            keypair=keypairs0[0])

    time1 = int(time.time())
    print("2-second interval.")
    time.sleep(2)

    tx = idPubkeyMap.update(user_id, public_keys_to_remove=public_keys,
            keypair=keypairs0[0])

    time2 = int(time.time())
    print("2-second interval.")
    time.sleep(2)

    tx = idPubkeyMap.update(user_id, public_keys_to_replace=public_keys,
            keypair=keypairs0[0])

    time3 = int(time.time())

    public_keys = idPubkeyMap.get_mapped_public_keys(user_id, time3)

    assert len(public_keys) == 3

    for keypair in keypairs1:
        assert bytes(keypair.public_key) in public_keys

    assert idPubkeyMap.is_mapped(user_id, keypairs0[0].public_key, time3) == False
    assert idPubkeyMap.is_mapped(user_id, keypairs1[0].public_key, time3) == True
    assert idPubkeyMap.is_mapped(user_id, keypairs1[1].public_key, time3) == True
    assert idPubkeyMap.is_mapped(user_id, keypairs1[2].public_key, time3) == True

    public_keys = idPubkeyMap.get_mapped_public_keys(user_id, time2)

    assert len(public_keys) == 1

    for keypair in keypairs0:
        assert bytes(keypair.public_key) in public_keys

    assert idPubkeyMap.is_mapped(user_id, keypairs0[0].public_key, time2) == True
    assert idPubkeyMap.is_mapped(user_id, keypairs1[0].public_key, time2) == False
    assert idPubkeyMap.is_mapped(user_id, keypairs1[1].public_key, time2) == False
    assert idPubkeyMap.is_mapped(user_id, keypairs1[2].public_key, time2) == False

    public_keys = idPubkeyMap.get_mapped_public_keys(user_id, time1)

    assert len(public_keys) == 4

    for keypair in keypairs0:
        assert bytes(keypair.public_key) in public_keys
    for keypair in keypairs1:
        assert bytes(keypair.public_key) in public_keys

    assert idPubkeyMap.is_mapped(user_id, keypairs0[0].public_key, time1) == True
    assert idPubkeyMap.is_mapped(user_id, keypairs1[0].public_key, time1) == True
    assert idPubkeyMap.is_mapped(user_id, keypairs1[1].public_key, time1) == True
    assert idPubkeyMap.is_mapped(user_id, keypairs1[2].public_key, time1) == True

    public_keys = idPubkeyMap.get_mapped_public_keys(user_id, time0)

    assert len(public_keys) == 1

    for keypair in keypairs0:
        assert bytes(keypair.public_key) in public_keys

    assert idPubkeyMap.is_mapped(user_id, keypairs0[0].public_key, time0) == True
    assert idPubkeyMap.is_mapped(user_id, keypairs1[0].public_key, time0) == False
    assert idPubkeyMap.is_mapped(user_id, keypairs1[1].public_key, time0) == False
    assert idPubkeyMap.is_mapped(user_id, keypairs1[2].public_key, time0) == False

    idPubkeyMap._BBcIdPublickeyMap__clear_local_database(user_id)
    print("cleared local database entries for the user for reconstruction.")

    public_keys = idPubkeyMap.get_mapped_public_keys(user_id)

    assert len(public_keys) == 3

    for keypair in keypairs1:
        assert bytes(keypair.public_key) in public_keys

    assert idPubkeyMap.is_mapped(user_id, keypairs0[0].public_key) == False
    assert idPubkeyMap.is_mapped(user_id, keypairs1[0].public_key) == True
    assert idPubkeyMap.is_mapped(user_id, keypairs1[1].public_key) == True
    assert idPubkeyMap.is_mapped(user_id, keypairs1[2].public_key) == True


# end of tests/test_id_lib.py
