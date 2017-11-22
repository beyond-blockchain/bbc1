Common classes for core and app
===================================
The classes in this directory are used by both core and app.

### bbclib.py
This library is very important because it determines the data format of transaction data itself and provides how to create, serialize, deserialize, sign and verify a transaction. BBcTransaction, BBcEvent, BBcReference, BBcAsset, BBcCrossRef and BBcSignature classes correspond to the whole transaction, an event, a reference, an asset in the event, a cross-reference (for proof of existence) and a signature of a transaction, respectively.

Message class is also defined in this library. This is internal use only for message handling between bbc_core and bbc_app.

The library includes some utilities for generating key pairs (KeyPair class) and so on. KeyPair class at this point supports Elliptic Curve Cryptography (ECDSA) only. This class provides some methods for generating, encoding and decoding key pairs.

### libbbcsig/libbbcsig.c
This is a utility for signing/verifying a transaction and generating a keypair. The functions are called through ctypes of python.

### message_key_types.py
This library is for building/parsing a message. Currently, BBc-1 uses [msgpack](https://msgpack.org) for serialization/deserialization of message because of ease of implementation. However, in the near future, we will move to general Type-Length-Value-based binary format. Such functions will be also included in this script.

### bbc_error.py
This file defines the error code in BBc-1.

### logger.py
This is a utility for logging service.

