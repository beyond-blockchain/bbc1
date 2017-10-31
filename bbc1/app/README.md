SDK for BBc-1 applications
==========================
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
