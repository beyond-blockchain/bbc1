Change log
======

## v1.0.1
* Bug fixes
  * pip install bug is fixed but pipenv install still has some troubles.
  * Bug of serialization/deserialization of BBcSignature in some cases is fixed

## v1.0
* Restructure the whole package
  * Only bbc1/core/ remains
  * Ledger_subsystem related codes and libraries are separated into other repositories
* Support BSON (binary JSON) format for transaction data structure
* Documents are updated
* Utilities are re-designed
* Bug fixes

## v0.10
* The core part is totally re-designed
  * user_message_routing.py, data_handler.py, topology_manager.py, key_exchange_manager.py, key_exchange_manager.py are newley added
  * inter-nodes and core-app communications are secured by AES256 encryption
* Implement domain/node key verification for administrative messages
* Scheme for recovery of forged transaction data is modified
  * A user (bbc_app) explicitly triggers the recovery when it obtains forged transaction data
* Anycast support
* Add currency library (token_lib)
* Add a new search method to obtain series of transaction data
* Cross_ref support

## v0.9.1
* Add libraries for token and id management

## v0.9
* Change APIs in bbc_app.py (remove asset_group_id options)
* Modify schemas of bbc_ledger tables
* Introduce BBcRelation/BBcPointer/BBcWitness class as parts of BBcTransaction
* Fix several bugs

## v0.8.2
* Eliminate the concept of "registering asset_group_id" to bbc_core
* Unlimit the size of BBcAsset body
* Default off for ledger_subsystem ('use_ledger_subsystem' item is introduced in config.json)
* Fix several bugs

## v0.8.1
* IPv6 support
* Fix several bugs

## v0.8
* Implement system statistics API #8
* Notification of transaction insertion is implemented #9
* NAT traversal support (only for simple port forwarding) #11
* user_id based transaction search #16
* Windows support for libbbcsig library

## v0.7.4
* Fix issues regarding ledger_subsystem #26, #27
* Refactor ledger_subsystem
* Fix populus version in requrements.txt

## v0.7.3
* Fix issues regarding installation #17, #21
* Modify sign/verify scheme in bbclib.py internally and add read function for PEM format key
* Remove unnecessary python module from requirements.txt

## v0.7.2
* Use OpenSSL for signing/verifying a transaction

## v0.7.1
* Bug fix
  - TCP message wait loop in bbc_network.py
 
## v0.7
Initial version
