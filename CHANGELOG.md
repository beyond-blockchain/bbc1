Change log
======

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
