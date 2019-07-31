The core of BBc-1
=================
The files in this directory is the main codes of BBc-1.

## BBc core codes
* bbc_core.py
    - The core of BBc-1 that processes transaction and communicates with applications (e.g., bbc_app)
    - The messages between BBcAppClient and BBcCoreService (in bbc_core.py) depends on [pickle](https://docs.python.org/3.6/library/pickle.html#module-pickle), data serialization tool in Python, because this project shows a reference of the implementation of BBc-1 and the concrete implementation of messaging is fully left to developers. The important thing here is *what function of bbc_core the application can use*. Therefore, the reference use pickle to show it simply. (Of course, the reference implementation will work fine.)
* bbc_app.py
    - Base interface for BBc-1 application
    - bbc_app connects to bbc_core to send/receive messages
    - All applications and management tools are based on it
* bbc_network.py
    - Communication management between other bbc_core nodes
    - BBcNetwork provides an interface to BBcCoreService to encapsulate the network layer functions, such as P2P topology management and message forwarding.
    - DomainBase class is a base class for networking functions. By overriding it, any kind of networking layer can be implemented. This project includes a simple networking function with full-mesh topology (see [Network module below](#nwmodule)).
* data_handler.py
    - Database manipulation for storing/searching transaction data, asset IDs, etc..
    - An auxiliary database is also managed here. It manages various useful information regarding transactions to improve efficiency of processing transactions.
    - Asset file management
* topology_manager.py
    - Neighbor node management for each domain
* user_message_routing.py
    - Message routing among users
* repair_manager.py
    - Perform forged data recovery when client application gives it a trigger
* domain0_manager.py
    - Processing cross_ref messages among domain_global_0 nodes, meaning that it works as a gateway node for a 
    cross_ref messages  

## Others
* query_management.py
    - Utility classes for managing timer operation such as message retransmission
    - Ticker class is a simple scheduler that counts the present time and fires the callback method if a timer object expires.
    - QueryEntry class is for a single timer object. It can hold some callbacks and parameter data for the callbacks.
* key_exchange_manager.py
    - Secret key exchange manager using ECDH
    - Keys are used for securing communication channel between core nodes, and between core node and bbc_app client
* bbc_config.py
    - Configuration management
    - A BBcConfig object creates and a read config file and the object is shared among BBcXXX objects.
* bbc_stats.py
    - Manage statistics information of bbc_core
* command.py
    - Argument parser of bbc_core.py
