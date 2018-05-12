Utilities
=========
Scripts in this directory are utilities for managing bbc_core, namely domain configuration.

*bbc\_domain\_config.py* is a edit tool of config.json for bbc_core.py. *bbc\_domain\_update.py* is a live config update tool. *bbc\_info.py* shows the statistics of a core node. *bbc\_ping.py* is a network configuration tool to establish a neighbor relationship with anothor core node. *domain\_key\_setup.py* is a secret key setup tool to secure admin message within a domain. *id\_create.py* is a utility to generate 256-bit ID in HEX string.


## common parameters

For bbc\_domain\_update.py, bbc\_info.py, bbc\_ping.py and domain\_key\_setup.py have same parameters to connect to a bbc\_core.py.

* -4: IPv4 address of the node running bbc\_core.py
* -6: IPv6 address of the node running bbc\_core.py
* -p: TCP port number where bbc_core.py is waiting for new connections

If these parameters are omitted, the default values, 127.0.0.1 for IPv4, ::1 for IPv6 and 9000 for TCP port, are used.

Furthermore, a node\_key would be required for the communication between bbc_core.py and a utility. In such a case, -k option designates a key file of node key.

## bbc\_domain\_config.py

bbc\_domain\_config.py creates and updates the config file of bbc_core.py, i.e., config.json.

-t option specifies the operation mode from generate, write and delete. The following command generate a new config 
file in the working directory .bbc1/.
```
python bbc_domain_config.py -t generate -w .bbc1/
```
Note that if there is no config file in the working directory, bbc\_core.py will generate the default config file, of
 which content is the same as the result above.

In the existence of config file in the working directory, "-t write" and "-t delete" edit the config file, i.e., 
config.json. The following command add a default domain config in config.json. 
```
python bbc_domain_config.py -t write -w .bbc1/ -d ffe65f1d98fafedea3514adc956c8ada5980c6c5d2552fd61f48401aefd5c00e 
``` 
The content of the comand result is like following:
```python
 'ffe65f1d98fafedea3514adc956c8ada5980c6c5d2552fd61f48401aefd5c00e': {
    'db': {
         'db_name': 'bbc_ledger.sqlite',
         'db_servers': [{'db_addr': '127.0.0.1',
                         'db_pass': 'pass',
                         'db_port': 3306,
                         'db_user': 'user'}],
         'db_type': 'sqlite',
         'replication_strategy': 'all'
    },
    'node_id': '',
    'static_nodes': {},
    'storage': {'type': 'internal'}
 },
```

In write mode, -k1 and -v options can add or update the item. For example by the following command:
```
python bbc_domain_config.py -t write -w .bbc1/ -d ffe6...(snip)...c00e -k1 db -k2 db_name -v test.db
```
the config of the domain will be changed as follows:
```python
 'ffe65f1d98fafedea3514adc956c8ada5980c6c5d2552fd61f48401aefd5c00e': {
    'db': {
         'db_name': 'test.db',
         'db_servers': [{'db_addr': '127.0.0.1',
                         'db_pass': 'pass',
                         'db_port': 3306,
                         'db_user': 'user'}],
         'db_type': 'sqlite',
         'replication_strategy': 'all'
    },
    'node_id': '',
    'static_nodes': {},
    'storage': {'type': 'internal'}
 },
```
-k1 is for the first level in the domain part, such as 'db', 'node_id', 'static_nodes' and 'storage', and -k2 is for 
the second level, such as 'db_name', 'db_servers' and so on. You can also set json style object value as follows:
```
python bbc_domain_config.py -t write -w .bbc1/ -d ffe6...(snip)...c00e -k1 db -v '{"db_type": "sqlite", "db_name": "test2.sqlite"}'
```
The command rewrites the part of 'db' only. The result is as follows:
```python
 'ffe65f1d98fafedea3514adc956c8ada5980c6c5d2552fd61f48401aefd5c00e': {
    'db': {
         'db_name': 'test2.db',
         'db_type': 'sqlite',
    },
    'node_id': '',
    'static_nodes': {},
    'storage': {'type': 'internal'}
 },
```

"-t delete" mode is for deleting the specified item. For example, if you want to delete 'node_id', the command is as 
follows:
```
python bbc_domain_config.py -t delete -w .bbc1/ -d ffe6...(snip)...c00e -k1 node_id
```

After editing the config file by this command, you need to notify bbc\_core.py of the modification.


## bbc\_domain\_update.py

The config file "config.json" is loaded only at the bootstrap of bbc_core.py. bbc\_domain\_update.py performs the 
online update of the configuration of the specified domain.

The following command notifies bbc_core.py of creating a new domain (ffe65f1....d5c00e) which has newly added in the 
config file. (-a is for addition)
```
python bbc_domain_update.py -d ffe65f1d98fafedea3514adc956c8ada5980c6c5d2552fd61f48401aefd5c00e -a
```

-r option is for removing a domain, which results in removing the part for the domain in config.json.
```
python bbc_domain_update.py -d ffe65f1d98fafedea3514adc956c8ada5980c6c5d2552fd61f48401aefd5c00e -r
```


## bbc\_info.py

The following command obtains the statistics information in the core node.

```
python bbc_info.py
```
The information is in a json format.


## bbc\_ping.py

When you send a ping message from a core node to another, each node recognizes each other and registers it in the neighbor list.
```
python bbc_ping.py domain_id dst_address dst_port
```

An example case is as follows:
There are two nodes with IPv4 addresses, 192.168.10.5 (node_A) and 192.168.10.6 (node_B). The port for inter connection between core nodes is 6641 by default. Assume that the following command is executed on node_A.
```
python bbc_ping.py -4 localhost -p 9000 ffe65f1d98fafedea3514adc956c8ada5980c6c5d2552fd61f48401aefd5c00e 192.168.10.6 6641
```

By this command, a ping message is sent to node_B, which automatically responds with ping responce message to node_A. As a result, both node_A and node_B registeres a new entry in their neighbor list, so that they recognize each other.

## domain\_key\_setup.py

A domain key is a AES256 encryption key for securing admin message with in a domain. The same key must be shared by all core nodes in the domain. Messages for setting up network configuration and so on are admin ones. A core node requires to include the signature by the domain key in the admin messages.
The domain key file should be placed in the directory specified in "domain_key" section in the config file. domain\_key\_setup.py generates a domain key by the following command:
```
python domain_key_setup.py -g -d ffe65f1d98fafedea3514adc956c8ada5980c6c5d2552fd61f48401aefd5c00e --dir domain_dir/
```
-g is for generating a key and -d specifies domain_id. --dir is for the key directory. Note that this command just generate a key file. To load the new key in bbc_core.py process, we have two ways as follows:
* Restarting bbc_core.py reloads all config files including domain key files.
* Sending notification to bbc_core.py (by the command below) triggers to reload domain_keys.
```
python domain_key_setup.py -n
```
Of course, -4, -6, -p and -k need to be given if needed.


## id\_create.py

Seed string is required to generate 256-bit ID string.
```
python id_create.py -s test-string
```
You will get the HEX string "ffe65f1d98fafedea3514adc956c8ada5980c6c5d2552fd61f48401aefd5c00e".

By adding -t option, timestamp of the current time is appended to the seed string.
```
python id_create.py -s test-string -t
```
You will see a different result at every trial.

If you want to get random ID string, -r generate such a string.
```
python id_create.py -r
```
