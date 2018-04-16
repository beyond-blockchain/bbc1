SDK for BBc-1 applications
==========================
## bbc_app.py
bbc_app.py contains utility classes for communication with a core node.

### BBcAppClient
The class includes methods to issue commands to a core node, more precisely, the BBcCoreService object in a node (referred to as bbc_core in this document). The class has a message wait loop to receive messages from the bbc_core. When BBcAppClient is instantiated, the object connects to a bbc_core and the message wait loop automatically starts. By calling methods of BBcAppClient, a message is sent to the bbc_core.

The following methods are for application configuration, so that they should be called when setting up the application:
* set_callback()
* set_user_id()
* set_asset_group_id()

The following methods are for system configuration. System administorators would use these methods.
* add_domain_id()
* domain_setup()
* set_domain_static_node()
* get_domain_peerlist()
* send_domain_ping()
* register_asset_group()
* get_bbc_config()
* manipulate_ledger_subsystem()

The following methods are internal use only.
* make_message_structure()
* send_msg()
* start_receiver_loop()
* receiver_loop()

The messages between BBcAppClient and BBcCoreService (in core/bbc_core.py) depends on [pickle](https://docs.python.org/3.6/library/pickle.html#module-pickle), data serialization tool in Python, because this project shows a reference of the implementation of BBc-1 and the concrete implementation of messaging is fully left to developers. The important thing here is *what function of bbc_core the application can use*. Therefore, the reference use pickle to show it simply. (Of course, the reference implementation will work fine.)

### Callback
The class is a base class for callback when receiving a message from bbc_core. By overriding methods in Callback class like proc_cmd_* and proc_resp_* methods, you can implement any message processing as you want.
In the callback, queue is used by default. Because the received message is a one of multi threads, queue is for inter-thread communication. If you want, you can call synchronize() method in the Callback object to wait and get a message from bbc_core. If you don't want to use queue, you can override the methods by your own code.


### utility methods for ID-String mapping
The mapping information is stored in .bbc_id_mappings (JSON file). These methods are just for testing, so they would be replaced by other sophisticated utilities.
* store_id_mappings
* remove_id_mappings
* get_id_mappings


## app_support_lib.py
app_support_lib.py contains utility functions and classes for application development. In particular, it provides functionality to create an application-support directory and a database class that currently supports SQLite3 only, whose files would reside in the application-support directory.


## id_lib.py
id_lib.py contains a class whose objects provide autonomous generation of user identifiers and mapping between a set of public keys and a generated identifier. The mapping can be updated by some designated authority (currently, just by the user represented by the identifier) in a domain. The class also provides standard means to verify that a transaction is signed by correct user or users in light of the mapping.

The following methods are provided:
* create_user_id() to autonomously create a user identifier and its initial mapping to a set of public keys.
* get_mapped_public_keys() to receive public keys mapped to an identifier at a given time.
* is_mapped() to see whether an identifier and a public key are (were) mapped at a given time.
* update() to update the mapping.
* verify_signers() to verify the correctness of signers to a transaction.


## token_lib.py
token_lib.py contains a mint class to deal with creation, transfer and destruction of currency tokens. The face value of such tokens can vary over time according to pre-programmed settings. Such settings can be switched according to external events (represented as a conditional change to the mint).

The following methods are provided:
* get_balance_of() to receive (estimated) token balance of a user at a given time.
* get_condition() to receive the condition (in the form of numbers) of the mint.
* get_currency_spec() to receive the specifications of the tokens.
* get_total_supply() to receive the total (estimated) token balance at the mint.
* issue() to issue a token to a user.
* set_condition() to set the condition (in the form of numbers) of the mint.
* set_currency_spec() to set the specifications of the tokens.
* set_keypair() to set the key-pair used for automatically responding to sign requests.
* transfer() to transfer tokens from a user to another user.










