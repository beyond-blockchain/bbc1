pytest
======
Please use pytest for testing.

testutils.py includes utility for setting up core and app, so it is not a test code itself.

* pytest test_bbclib.py
* pytest test_bbc_app.py -m register
  - need to run python bbc_core.py
* pytest test_bbc_storage.py
* pytest test_bbc_ledger.py

bash
* pytest test_bbc_network_with_core.py > log.test 2>& 1
