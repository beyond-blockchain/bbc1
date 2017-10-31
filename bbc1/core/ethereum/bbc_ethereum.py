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
import binascii
import hashlib
import os
import sys
from populus import Project
from populus.utils.wait import wait_for_transaction_receipt
from web3 import Web3

class BBcEthereum:
    """
    Abstraction of an Ethereum version of a proof of existnce contact.
    """
    def __init__(self, account, passphrase, contract_address=None):
        """
        Constructs the contract object.

        :param account: Ethereum account in hexadecimal prefixed with '0x'
        :param passphrase: Passphrase to unlock the account
        :param contract_address: Deployed contract (if None, it deploys one)
        :return:
        """
        project = Project()
        chain_name = "bbc"

        with project.get_chain(chain_name) as chain:

            AnchorFactory = chain.provider.get_contract_factory('BBcAnchor')

            chain.web3.personal.unlockAccount(account, passphrase)

            if contract_address == None:
                txid = AnchorFactory.deploy(
                    transaction={"from": account},
                    args=[]
                )
                contract_address = chain.wait.for_contract_address(txid)

            self.account = account
            self.anchor = AnchorFactory(address = contract_address)
            self.chain = chain


    def blockingSet(self, digest):
        """
        Registeres a digest in the contract.

        :param digest: Digest to register
        :return:
        """
        if type(digest) == bytes:
            digest0 = int.from_bytes(digest, 'big')
        else:
            digest0 = digest
        txid = self.anchor.transact(
            transaction={"from": self.account}
        ).store(digest0)
        self.chain.wait.for_receipt(txid)


    def get_contract_address(self):
        """
        Returns the contract address.

        :return: the contract address of the deployed BBcAnchor
        """
        return self.anchor.address


    def test(self, digest):
        """
        Verifies whether the digest (Merkle root) is registered or not.

        :param digest: Digest (Merkle root) to test existence
        :return: 0 if not found, otherwise the block number upon registration
        """
        if type(digest) == bytes:
            digest0 = int.from_bytes(digest, 'big')
        else:
            digest0 = digest
        return self.anchor.call().getStored(digest0)


    def verify(self, digest, subtree):
        """
        Verifies whether the digest is included in the registered Merkle tree.

        :param digest: Digest to test existence
        :param subtree: Merkle subtree to calculate the root
        :return: 0 if not found, otherwise the block number upon registration
        """
        for dic in subtree:
            digest0 = binascii.a2b_hex(dic['digest'])
            if dic['position'] == 'right':
                dLeft = digest
                dRight = digest0
            else:
                dLeft = digest0
                dRight = digest
            digest = hashlib.sha256(dLeft + dRight).digest()

        return self.test(digest)


if __name__ == '__main__':

    # simple test code and usage
    a = BBcEthereum(sys.argv[1], sys.argv[2], sys.argv[3])

    a.blockingSet(0x1234)
    print(a.test(0x1230))
    print(a.test(0x1234))

    a.blockingSet(b'\x43\x21')
    print(a.test(0x4321))
    print(a.test(b'\x43\x21'))


# end of core/ethereum/bbc_ethereum.py
