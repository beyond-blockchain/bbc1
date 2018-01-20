Core system of BBc-1 (Beyond Blockchain One)
===========================================
This project is a Python-based reference implementation of BBc-1, a trustable system of record keeping beyond blockchains.

The design paper (white paper) and the analysis paper are available [here](https://beyond-blockchain.org/public/bbc1-design-paper.pdf) and [here](https://beyond-blockchain.org/public/bbc1-analysis.pdf). BBc-1 is inspired from blockchain technologies like Bitcoin, Ethereum, Hyperledger projects, and so on.
BBc-1 is a simple but reliable distributed ledger system in contrast with huge and complicated existing blockchain platforms.
The heart of BBc-1 is the transaction data structure and the relationship among transactions, which forms a graph topology.
A transaction should be signed by the players who are the stake holders of the deal. BBc-1 achieves data integrity and data transparency by the topology of transaction relationship and signatures on transactions. Simply put, BBc-1 does not have *blocks*, and therefore, requires neither mining nor native cryptocurrency.
BBc-1 can be applied to both private/enterprise use and public use. BBc-1 has a concept of *domain* for determining a region of data management. Any networking implementation (like Kademlia for P2P topology management) can be applied for each domain.
Although there are many TODOs in BBc-1, this reference implementation includes most of the concept of BBc-1 and would work in private/enterprise systems. When sophisticated P2P algorithms are ready, BBc-1 will be able to support public use cases.

Every directory includes README.md. Please read it for the details. Furthermore, directory docs/ includes documents and slide decks (PDF) that explain the design of the BBc-1 and its implementation.

# Environment

* Python
    - Python 3.6.0 or later

* tools for macOS by Homebrew
    ```
    brew install libtool automake geth solidity pkg-config
    ```

* tools for Linux (Ubuntu 16.04 LTS)
    ```
    sudo apt-get install -y git tzdata openssh-server python3 python3-dev python3-venv libffi-dev net-tools autoconf automake libtool libssl-dev make
    ```


# Quick start

## Documents
Some documents are available in docs/.
* [how_to_use_in_nat_environment.md](docs/how_to_use_in_nat_environment.md)


## From source code in github
1. Install tools (libtool, automake)
2. Install python and pip
3. Clone this project
4. Prepare OpenSSL-based library in the root directory
    ```
    sh prepare.sh
    ```
5. Install dependencies by the following command.
    ```
    pip install -r requirements.txt
    ```
6. Start bbc_core.py on a terminal
    ```
    cd core
    python bbc_core.py
    ```
7. Start a sample app in another terminal
    ```
    cd examples
    python file_proof.py arg1 arg2..
    ```


## Use pip
1. Install tools (libtool, automake)
2. Install python and pip
3. Install BBc1 by pip
    ```
    pip install bbc1
    ```

## Use docker (See README.md in docker/)
0. Install docker on your host
1. Clone this project
2. Build docker image
    If you want source codes in your container,
    ```
    cd docker
    ./docker-bbc1.sh gitbuild
    ```
    or, if you just want to use BBc-1,
    ```
    cd docker
    ./docker-bbc1.sh pipbuild
    ```
3. Run a docker container
    ```
    ./docker-bbc1.sh start
    ```
4. Log in to the container
    ```
    ./docker-bbc1.sh shell
    ```
    or
    ```
    ssh -p 10022 root@localhost
    ```
    The initial password is "bbc1".

### working directory
The working directory of BBc-1 on the docker container is mounted on docker/data/.bbc1/. You will find a config file, ledger DB and file storage directory in the working directory.


# Files/Directories
* core/
    - core functions of BBc-1
* app/
    - SDK for applications using BBc-1
* common/
    - libraries and utilities for both core and app
* utils/
    - BBc-1 system configuration utilities
* examples/
    - sample applications on BBc-1
* docker/
    - docker environments
* tests/
    - test codes for pytest
* docs/
    - docs about BBc-1 and its reference implementation
* somewhere/.bbc1/
    - default working directory name of bbc_core.py
* requirements.txt
    - python modules to be required
* setup.py
* MANIFEST.in
* prepare.py
    - for creatign python modules
