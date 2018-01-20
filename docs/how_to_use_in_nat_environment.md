How to deploy BBc-1 in cloud and/or NAT environment

# Introduction
Aiming to create a BBc-1 network constructed with nodes working in various environments,
this document explains how to deploy and connect BBc-1 node in a cloud and/or NAT environment.


# Expected Environments
We expects to deploy BBc-1 into a (virtual) host working in a network as the following diagram.
```
node 1 [bbc_core]
< ipv4 private address: A.A.A.A, exposed port: P1 >
   │
NAT gateway 1
< ipv4 global address: X.X.X.X, exposed port: P1 (forwarding to node 1) >
   │
The Internet
   │
NAT gateway 2
< IPv4 global address: Y.Y.Y.Y, exposed port: P2 (forwarding to node 2) >
   │
node 2 [bbc_core]
< ipv4 private address: B.B.B.B, exposed port: P2 >
```

For instance of Microsoft Azure, each virtual machine has one virtual network interface in default, and it get assigned a private IPv4 address from NAT gateway due to the security reason.  In such an environment, although it, of course, get assigned unique global IPv4 address, there is no way for such a virtual node to *implicitly* notify external nodes its global IPv4 address in the standard sequence of BBc-1 connection establishment.

So, here we shall explain how to set up BBc-1 instances and connect them with one another by *explicitly* specifying its reachable global IPv4 address.

This procedure can be applied to any kind of NAT environment with appropriate static port forwarding at NAT gateway.

NOTE: *NAPT (dynamic IP masquerading) is not supported at this point (v0.8). We should configure static port forwarding at gateways in private networks.*

# Environments
First of all, we need to install several packages into every node (`node 1` and `node 2` in the above diagram) in the exactly same manner as
[Quick Start](https://github.com/beyond-blockchain/bbc1/blob/develop/README.md).

For macOS High Sierra:
```shell
$ brew update
$ brew install python3 libtool automake geth solidity pkg-config
```

For Ubuntu 16.04 LTS:
```shell
$ sudo apt-get update
$ sudo apt-get install -y git tzdata openssh-server python3 python3-dev python3-venv libffi-dev net-tools autoconf automake libtool libssl-dev make
```

# Setup BBc-1
The setup procedure is almost same as well as [Quick Start](https://github.com/beyond-blockchain/bbc1/blob/develop/README.md). At both `node 1` and `node 2`, we should setup the base of BBc-1 as follows. Note that the following procedure shows the case of installation into the native environment.

```shell
# bbc1 source is retrieved
$ git clone git@github.com:beyond-blockchain/bbc1.git
$ cd bbc1
$ git checkout develop

# openssl is retrieved and compiled
$ bash prepare.sh

# install required pypi packages into virtualenv
$ python3 -m venv .bbc1_venv
$ source .bbc1_venv/bin/activate
(.bbc1_venv)$ pip install -r requirements.txt
(.bbc1_venv)$ deactivate
```
After the above setup procedure, we are ready to run the BBc-1 in a standalone manner.

# Configure your domain
In order to connect multiple BBc-1 nodes with each other in the same *domain* right after its instantiation, we may need to prepare a small configuration file.

The following JSON is just an example of *minimum* configuration file. The detailed options is explained [here (bbc1/utils/README.md)](https://github.com/beyond-blockchain/bbc1/blob/develop/utils/README.md). The first key value, i.e., b7035..., is the *domain id* that would be established simultaneously with BBc-1 instantiation.

```json:config.json
{
  "da799b7ffbf94e7908982c36e7ebfa6a1ae6c9744b4d24d241f711a5d6d0eacd": {
    "module": "simple_cluster",
    "asset_group_ids": {
    },
    "static_nodes": {
    }
  }
}
```

The domain id can be generated from our desired string in the following manner.

```shell
$ cd /path/to/bbc1
$ source .bbc1_venv/bin/activate
(.bbc1_venv)$ cd utils
(.bbc1_venv)$ python bbc_system_conf.py -i "desired string"
da799b7ffbf94e7908982c36e7ebfa6a1ae6c9744b4d24d241f711a5d6d0eacd
```

The configuration file, say `config.json`, needed to get copied to every node, i.e., `node 1` and `node 2`.

# Run and connect BBc-1 with external nodes
Now we are ready to create a BBc-1 networks with multiple nodes in multiple distinct networks. To this end, we first execute
```shell
$ python ./bbc_core.py -pp <exposed port> --ip4addr <ipv4 address reachable to the node>
```
and instantiate BBc-1 node with the configured domain by
```shell
$ python ./bbc_system_conf.py <configuration file>
```

In particular, from the diagram given in the head of this document, we see that `node 1` and `node 2` can be reachable with `X.X.X.X:P1` and `Y.Y.Y.Y:P2`, respectively. Then, we run `bbc_core.py` and instantiate BBc-1 nodes at `node 1` and `node 2` by executing the following commands.

- At `node 1`:
```shell
$ cd /path/to/bbc1
$ source .bbc1_venv/bin/activate
(.bbc1_venv)$ cd bbc1/core
(.bbc1_venv)$ python ./bbc_core.py -d -pp P1 --ip4addr X.X.X.X -l /var/tmp/bbc1.log
(.bbc1_venv)$ cd ../../utils/
(.bbc1_venv)$ python ./bbc_system_conf.py /path/to/config.json
  ```
- At `node 2`:
```shell
$ cd /path/to/bbc1
$ source .bbc1_venv/bin/activate
(.bbc1_venv)$ cd bbc1/core
(.bbc1_venv)$ python ./bbc_core.py -d -pp P2 --ip4addr Y.Y.Y.Y -l /var/tmp/bbc1.log
(.bbc1_venv)$ cd ../../utils/
(.bbc1_venv)$ python ./bbc_system_conf.py /path/to/config.json
```

Then, we connect a node with the other node over the configured domain using `bbc_ping.py` as follows.
```shell
$ python bbc_ping.py <domain id> <destination address> <destination address>
```

For the case of `node 1` and `node 2` in the exemplary diagram, we execute the following commands.

- At `node 1`:
```shell
$ cd /path/to/bbc1
$ source .bbc1_venv/bin/activate
(.bbc1_venv)$ cd utils
(.bbc1_venv)$ python bbc_ping.py da799b7ffbf94e7908982c36e7ebfa6a1ae6c9744b4d24d241f711a5d6d0eacd Y.Y.Y.Y P2
```
- At `node 2`:
```shell
$ cd /path/to/bbc1
$ source .bbc1_venv/bin/activate
(.bbc1_venv)$ cd utils
(.bbc1_venv)$ python bbc_ping.py da799b7ffbf94e7908982c36e7ebfa6a1ae6c9744b4d24d241f711a5d6d0eacd X.X.X.X P1
```

# Check connection status
We can verify if the connection is successfully established and still flawlessly connected via `python bbc_system_conf.py -l`. If you are on the `node 1`, you see the list of connected nodes for each domain as follows.
```shell
$ cd utils
(.bbc1_venv)$ python ./bbc_system_conf.py -l
b'\xda\x79\x9b\x7f\xfb\xf9\x4e\x79\x08\x98\x2c\x36\xe7\xeb\xfa\x6a\x1a\xe6\xc9\x74\x4b'
====== peer list of domain:da799b7ffbf94e7908982c36e7ebfa6a1ae6c9744b4d24d241f711a5d6d0eacd =====
*myself*    b'afee3ecc', X.X.X.X, ::, P1
            b'bce7091e', Y.Y.Y.Y, ::, P2
```
