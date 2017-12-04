The core of BBc-1
=================
The files in this directory is the main codes of BBc-1.

## BBc core codes
* bbc_core.py
    - The core of BBc-1 that processes transaction and communicates with applications (e.g., bbc_app)
    - The messages between BBcAppClient and BBcCoreService (in bbc_core.py) depends on [pickle](https://docs.python.org/3.6/library/pickle.html#module-pickle), data serialization tool in Python, because this project shows a reference of the implementation of BBc-1 and the concrete implementation of messaging is fully left to developers. The important thing here is *what function of bbc_core the application can use*. Therefore, the reference use pickle to show it simply. (Of course, the reference implementation will work fine.)
* bbc_ledger.py
    - Database manipulation for storing/searching transaction data, asset IDs, etc..
    - An auxiliary database is also managed here. It manages various useful information regarding transactions to improve efficiency of processing transactions.
* bbc_storage.py
    - Asset file management
    - There are some options about *who stores assets*, and they can choose one of them for each domain.
    - BBcStorage class provides the methods to store and search asset files in/from the specified storage.
* bbc_network.py
    - Communication management between other bbc_core nodes
    - BBcNetwork provides an interface to BBcCoreService to encapsulate the network layer functions, such as P2P topology management and message forwarding.
    - DomainBase class is a base class for networking functions. By overriding it, any kind of networking layer can be implemented. This project includes a simple networking function with full-mesh topology (see [Network module below](#nwmodule)).
* ledger_subsystem.py
    - Anchoring to an existing blockchain system like Ethereum and Bitcoin
    - If ledger_subsystem is enabled, hash values (Merkle trees) of transactions are automatically registered to a blockchain system.
    - Currently, it supports registering hash values to Ethereum via smart contracts.

## <a name="nwmodule"> Network modules
* simple_cluster.py
    - bbc_nodes in a domain compose a full mesh topology and share the copies of any data
    - All transactions and assets are shared in all the bbc_core nodes in a domain.
* (p2p_kademlia.py)
    - bbc_nodes in a domain form a P2P network using Kademlia algorithm
    - Currently, it's under development. Coming soon.

## Others
* query_management.py
    - Utility classes for managing timer operation such as message retransmission
    - Ticker class is a simple scheduler that counts the present time and fires the callback method if a timer object expires.
    - QueryEntry class is for a single timer object. It can hold some callbacks and parameter data for the callbacks.
* bbc_config.py
    - Configuration management
    - A BBcConfig object creates and a read config file and the object is shared among BBcXXX objects.
* command.py
    - Argument parser of bbc_core.py
