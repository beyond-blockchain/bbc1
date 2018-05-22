Core system of BBc-1 (Beyond Blockchain One)
===========================================
![travisCI](https://travis-ci.org/beyond-blockchain/bbc1.svg?branch=develop)

This project is a Python-based reference implementation of BBc-1, a trustable system of record keeping beyond blockchains.

The design paper (white paper) and the analysis paper are available [here](https://beyond-blockchain.org/public/bbc1-design-paper.pdf) and [here](https://beyond-blockchain.org/public/bbc1-analysis.pdf). BBc-1 is inspired from blockchain technologies like Bitcoin, Ethereum, Hyperledger projects, and so on.
BBc-1 is a simple but reliable distributed ledger system in contrast with huge and complicated existing blockchain platforms.
The heart of BBc-1 is the transaction data structure and the relationship among transactions, which forms a graph topology.
A transaction should be signed by the players who are the stake holders of the deal. BBc-1 achieves data integrity and data transparency by the topology of transaction relationship and signatures on transactions. Simply put, BBc-1 does not have *blocks*, and therefore, requires neither mining nor native cryptocurrency.
BBc-1 can be applied to both private/enterprise use and public use. BBc-1 has a concept of *domain* for determining a region of data management. Any networking implementation (like Kademlia for P2P topology management) can be applied for each domain.
Although there are many TODOs in BBc-1, this reference implementation includes most of the concept of BBc-1 and would work in private/enterprise systems. When sophisticated P2P algorithms are ready, BBc-1 will be able to support public use cases.

The source codes in this repository is a platform of BBc-1 and bbc\_core.py is the main process of a core node.
The APIs of BBc-1 is defined in bbc\_app.py and bbclib.py. So application developers should import them in your apps.
 For building a BBc-1 system, bbc1 package needs to be installed in the hosts and you need to run bbc\_core.py on
 each host. In order to configure the BBc-1 network, the utilities in utils/ directory are available. They are a kind
  of BBc-1 application, so that you can develop your own management tools.


For the details, please read documents in docs/ directory. Not only documents but slide decks (PDF) explain the design of the BBc-1 and its implementation.

## Documents
Some documents are available in docs/.
* Policy, design and analysis
  * [BBc-trust.pdf](docs/BBc-trust.pdf)
  * [BBc-trust_ja.pdf](docs/BBc-trust_ja.pdf)
  * [BBc-1_design_paper.pdf](docs/BBc-1_design_paper.pdf)
  * [BBc1_design_document_v1.0_ja.pdf](docs/BBc1_design_document_v1.0_ja.pdf)
  * [How_BBc1_works_v1.0_ja.pdf](docs/How_BBc1_works_v1.0_ja.pdf)
* Usage
    * [How_to_use_BBc1_v1.0_ja.pdf](docs/How_to_use_BBc1_v1.0_ja.pdf)
    * [BBc1_core_tutorial_installation_ja.md](docs/BBc1_core_tutorial_installation_ja.md)
    * [how_to_use_in_nat_environment.md](docs/how_to_use_in_nat_environment.md)
    * [libbbcsig_dll_build_for_Windows_x64_ja.md](docs/libbbcsig_dll_build_for_Windows_x64_ja.md)
* Programing
    * [BBc1_programming_guide_v1.0_ja.md](docs/BBc1_programming_guide_v1.0_ja.md)
    * [BBc1_core_tutorial_file_proof_ja.md](docs/BBc1_core_tutorial_file_proof_ja.md)
* API reference (Coming soon. Currently, something wrong in building docs)
    * [https://bbc-1.readthedocs.io/en/latest/](https://bbc-1.readthedocs.io/en/latest/)
    * You can read API docs in your local host by the following command:
        ```python
        cd docs/api/_build/html
        pipenv run python -m http.server
        ```


# Environment

* Python
    - Python 3.5.0 or later
    - [pipenv](https://docs.pipenv.org) is recommended
        - add ```export PIPENV_VENV_IN_PROJECT=true``` in .bash_profile

* tools for macOS by Homebrew
    ```
    brew install libtool automake python3 pipenv
    ```

* tools for Linux (Ubuntu 16.04 LTS)
    ```
    sudo apt-get install -y git tzdata openssh-server python3 python3-dev libffi-dev net-tools autoconf automake libtool libssl-dev make
    pip install pipenv
    ```


# Quick start

## From source code in github
1. Install development tools (libtool, automake)
2. Install python and pip
3. Clone this project
4. Prepare OpenSSL-based library in the root directory
    ```
    sh prepare.sh
    ```
5. Install dependencies by the following command (in the case of python 3.6)
    ```
    pipenv install
    pipenv shell
    ```
    Because Pipfile is configured for python version 3.6, use the following if your python version is not 3.6:
    ```
    pipenv install -r requirements.txt
    pipenv shell
    ```

6. Start bbc_core.py on a terminal
    ```
    cd core
    python bbc_core.py
    ```
7. Start a sample app in another terminal (should be initially at bbc1/ top directory)
    ```
    pipenv shell
    cd examples
    python file_proof.py arg1 arg2..
    ```


## Use pip
1. Install development tools (libtool, automake)
2. Install python and pip
3. Install BBc1 by pip
    ```
    pipenv install bbc1
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
* bbc1/core/
    - core functions of BBc-1
* utils/
    - BBc-1 system configuration utilities
* examples/
    - sample applications on BBc-1
* docker/
    - docker environments
* tests/
    - test codes for pytest
* libs/
    - some libraries used by BBc-1
* docs/
    - docs about BBc-1 and its reference implementation
* somewhere/.bbc1/
    - default working directory name of bbc_core.py
* requirements.txt
    - python modules to be required
* Pipfile, Pipfile.lock
    - python modules info for pipenv
* setup.py
* MANIFEST.in
* prepare.py
    - for creatign python modules
* prepare.sh
    - setup script
