# -*- coding: utf-8 -*-
import pytest

@pytest.fixture()
def anchor_contract(chain):
    AnchorFactory = chain.provider.get_contract_factory('BBcAnchor')
    deploy_txid = AnchorFactory.deploy(args=[])

    contract_address = chain.wait.for_contract_address(deploy_txid)
    return AnchorFactory(address=contract_address)

def test_my_token(anchor_contract, chain):

    account0 = chain.web3.eth.accounts[0]
    account1 = chain.web3.eth.accounts[1]

    digest0 = 0x000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f
    digest1 = 0x800102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f

    assert anchor_contract.call().isStored(digest0) == False
    assert anchor_contract.call().getStored(digest0) == 0

    txid = anchor_contract.transact().store(digest0)
    chain.wait.for_receipt(txid)

    assert anchor_contract.call().isStored(digest0) == True
    assert anchor_contract.call().getStored(digest0) > 0

    assert anchor_contract.call().isStored(digest1) == False

    txid = anchor_contract.transact().store(digest1)
    chain.wait.for_receipt(txid)

    assert anchor_contract.call().isStored(digest1) == True

# end of test_bbc_anchor.py
