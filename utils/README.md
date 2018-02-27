Utilities
=========
Scripts in this directory are utilities for managing bbc_core.

## common
All scripts take "-4", "-6" and "-p" options. They specify which bbc_core you connect to. Omitting them results in applying the default settings as follows: "127.0.0.1" and 9000. You can also use IPv6 by using "-6" option.

## bbc_system_conf.py
This script is a configuration tool to create a domain. JSON file is used for the configuration.

* Calculate ID from a given string
    ```
    python bbc_system_conf.py -i "some string"
    ```
    The above command always returns the same result as long as the parameter "some string" is the same.
    The following command creates a different ID because it appends a timestamp internally.
    ```
    python bbc_system_conf.py -t "some string"
    ```

* Get all socket information of all domains
    ```
    python bbc_system_conf.py -m
    ```
    You will get a dictionary data including {"domain_id": {"node_id": (ipv4, ipv6, port)}}. You will need the node_id to configure JSON file.

* Get all peer nodes of all domains the connecting bbc_core is joining
    ```
    python bbc_system_conf.py -l
    ```

* Get config file of the connecting bbc_core
    ```
    python bbc_system_conf.py -g
    ```
    You will get the config file of the bbc_core (typically in .bbc1/config.json.)

* Show sample config JSON file
    ```
    python bbc_system_conf.py -c
    ```
    Please save the result as a json file and edit it. The following is the sample json:
    ```
    {
        "*domain_id": {
            "module": "simple_cluster",
            "static_nodes": {
                "*node_id": "[*ipv4, *ipv6, *port]"
            },
            "asset_group_ids": {
                "*asset_group_id1": {
                    "storage_type": 1,
                    "storage_path": null,
                    "advertise_in_domain0": false
                },
                "*asset_group_id2": {
                    "storage_type": 1,
                    "storage_path": null,
                    "advertise_in_domain0": false
                }
            }
        }
    }
    ```
    *module* takes "simple_cluster" only at this point. This is a driver for composing a P2P network.
    *static_nodes* are the neighboring nodes that the bbc_core node tries to connect to.
    *storage_type* in asset_group_id entry takes 0 or 1, currently. This is from StorageType class in bbclib.py. If 0, asset files are never stored in bbc_core nodes.
    *storage_path* specifies the path in the bbc_core node to store asset files.
    *advertise_in_domain0* has not been supported yet. It is for cross_ref exchange for proof of existence.

* Send configuration
    ```
    python bbc_system_conf.py json_file_name
    ```
    Send and apply the configuration to the bbc_core node.

## bbc_ping.py
This script is a simplified tool to setup domain and static connection between two core_nodes.

* Create a domain and send domain_ping
    ```
    python bbc_ping.py domain_id dst_address dst_port
    ```
    If you use "-6" in addition, dst_address must be also IPv6 address. The same thing goes for "-4" or default.
    As a result of this command, the bbc_core creates a domain with the given domain_id. After creating the domain, the core sends *domain_ping* to the specified destination. When the receiver of domain_ping is joining the domain, the receiver adds the sender node as the peer node. Then, the receiver sends back a normal bbc ping message, so that the sender can find the receiver node as the peer node. Note that the receiver must have the specified domain_id. If not, nothing happens.

## bbc_setup.py
This script is for creating domain and updating peer list of the connecting bbc_core.

* Create a new domain
    ```
    python -d [domain_id_string]
    ```
    [domain_id_string] is a hex string of the domain ID.
    By default, the bbc_setup.py connects to the bbc_core at port 9000 on the localhost.
    If you want to specify the bbc_core, -4, -6 and -p options configures the IPv4, IPv6 and TCP port number to connect, respectively.

* Make the bbc_core send ping to its neighbors to update its peer list
    ```
    python -d [domain_id_string] --ping_to_neighbors
    ```

## subsystem_tool.py
This script is for the ledger_subsystem. You can enable/disable ledger_subsystem, and register/verify transaction_id in the ledger subsystem.

* Enable the subsystem
    ```
    python subsystem_tool.py --start
    ```

* Disable the subsystem
    ```
    python subsystem_tool.py --stop
    ```

* Register a transaction_id
    ```
    python subsystem_tool.py -a "hex string of asset_group_id" -t "hex string of transaction_id" --register
    ```
    asset_group_id and transaction_id are like the following: *e59c553504ca7a54f888eb47e61b773a221ae1311bd58ec4c0912d71c443d715*

* Verify a transaction_id
    ```
    python subsystem_tool.py -a "hex string of asset_group_id" -t "hex string of transaction_id" --verify
    ```
    You will get a result (and Markle subtree) in a JSON form. (Please modify how to retrieve/treat the result by yourself.)
