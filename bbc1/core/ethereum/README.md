Ledger subsystem with Ethereum for BBc-1
===
Files in this directory supports the ledger subsystem with Ethereum blockchain for BBc-1.
Currently supports local geth chain only.

## Ledger subsystem
* bbc_ethereum.py
  * abstraction of BBcAnchor smart contract that would store Merkle roots of transactions.
  * also provides verify function that takes a Merkle subtree for independent verification from BBc-1.
* contracts/BBcAnchor.sol
  * The BBcAnchor smart contract.
* setup.py
  * sets up Populus environment and geth Ethereum node. See usage below.
* ../core/ledger_subsystem.py
  * enable() to enable writing to the subsystem (or initialize with enabled=True).
  * disable() to disable writing to the subsystem.
  * set_domain(domain_id) to set relevant domain_id.
  * register_transaction(asset_group_id, transaction_id) to write the transaction_id into a Merkle tree.
  * verify_transaction(asset_group_id, transaction_id) to verify that the transaction exists and to receive the Merkle subtree.

## Dependencies
* populus 1.10.1 (note that rlp==0.5.1), 1.11.0-2.1.0, 2.2.0 (requires project.json from older environment)
* geth (go ethereum) 1.7.2, 1.7.3
* solc (solidity) 0.4.17, 0.4.18

## How to use
1. Set up populus environment
```
python setup.py populus
```
2. Set up genesis block of a local geth chain
```
python setup.py genesis
```
3. Set up a new Ethereum account
```
python setup.py new_account <passphrase>
```
4. Run the local geth chain
```
python setup.py run
```
For the first execution, this would take some tens of minutes for mining to be started.

5. Deploy BBcAnchor smart contract
```
python setup.py deploy
```

You are all set, and you can run ledger_subsystem with enabled=True argument or enable() it.

If your geth chain has already been mined, then you may want to try
```
python setup.py auto <passphrase>
```
to automatically set up everything (but beware that the contract address will be overwritten. Consider this as a testing feature, useful when BBc-1 configuration has been erased).

When you want to stop the local geth chain,
```
python setup.py stop
```
When you want to resume, just
```
python setup.py run
```
You do not need to set up an account or deploy the contract again.
The information is all written into the config file of BBc-1 core.

## Tests
* tests/test_bbc_ethereum.py --- run prior to test_ledger_subsystem.py
* tests/test_ledger_subsystem.py --- may need to be terminated by a keyboard interrupt.

