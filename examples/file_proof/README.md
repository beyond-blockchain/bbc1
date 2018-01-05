File proof
==========
This app allows a user to do the following:
* store a file in bbc_core
* update a file in bbc_core
* get a file from bbc_core
* verify a file
* send/receive a file to another user through bbc_core and transfer the possession of it

# How to use
1. Start bbc_core.py in a terminal
    ```
    cd ../../core
    python bbc_core.py
    ```
2. Create a key pair, and set up a domain and an asset group
    ```
    python file_proof.py keypair
    python file_proof.py setup
    ```
    .private_key and .public_key are created.
3. Execute commands in another terminal
    The commands must be executed in the directory having the key pair.
    * Store a file
        ```
        python file_proof.py store [filename]
        ```
        You can specify your user name by -o option.
        ```
        python file_proof.py store [filename] -o [username]
        ```
        username is converted into SHA-256 digest in the application.
    * Get a file
        ```
        python file_proof.py get [filename]
        ```
        You need to have stored the file before this command.
    * Update a file
        edit/update a file that has already been stored.
        ```
        python file_proof.py update [filename]
        ```
        -o option is also available.
    * Verify a file
        ```
        python file_proof.py vefify [filename]
        ```
        Of course, the file must be in the bbc_core for this to succeed.
    * Send/receive a file
        You need two terminals.
        ```
        python file_proof.py wait
        ```
        The above command is for the receiver.
        ```
        python file_proof.py send [filename]
        ```
        The above command is for the sender. The sender will see a prompt for the user name for the receiver. (Note that it is not user_id!)
        You can send/receive the file by following the interactive messages.
        After the file transfer, the receiver can get/verify the file by "get" and "verify" commands above.

## JSON file for utility
Basically, BBc-1 treats only 256-bit value (SHA-256 digest value) as an ID. It is not intuitive for application user/developer in some cases. So, bbc_app.py provides utilities for mapping betwen SHA-256 values and human-readable strings in a JSON file. You can see .bbc_id_mappings in the directory where file_proof.py is executed.

# Basic flow of file_proof.py
A process in file_proof.py includes two parts, preparation (the former half of the process) and individual mode operation (the latter half of it).

## Preparation
argument_parser() parses parameters to choose the operation mode.
sys_check() mainly read a key pair, which is saved in .private_key and .public_kdy in the current directory.
setup_bbc_client() calls method in bbc_app.py and connects/registers to bbc_core. In registering to bbc_core, domain_id, user_id, network module and so on are configured.
get_id_from_mappings() and store_id_mappings() reads/stores the JSON file that has the information of the mappings among a transaction_id, an asset_id and a file name. Basically, BBc-1 treats only 256-bit value (SHA-256 digest value) as an ID. It is not intuitive for application user/developer in some cases. So, bbc_app.py provides utilities for mapping between SHA-256 values and human-readable strings in a JSON file. You can see .bbc_id_mappings in the directory where file_proof.py is executed.


## Operation modes
### common thing
In each mode, queue system is utilized for message receiving from bbc_core. You can find several lines of ```response_data = bbc_app_client.callback.synchronize()```.

### store mode
store_file() and store_proc() work in this mode. store_proc() creates a transaction using bbclib.make_transaction_for_base_asset() and add the signature of yourself. Then, the transaction is inserted into the bbc_core by bbc_app_client.insert_transaction() method.

### update mode
store_file() and store_proc() also work in this mode. At the beginning of store_proc(), it searches for the existing transaction by using asset_id obtained from .bbc_id_mappings JSON file. Different from the store mode, the transaction involves a BBcReference object for the previous transaction (maybe the first registration of the file or the last update of it). The rest of the process is the same as store mode.

### get mode
get_file() works in this mode. By the file name, the corresponding asset_id (included in the last transaction regarding the file) obtained from .bbc_id_mappings JSON file. The transaction and the asset file are retrieved from the bbc_core by using bbc_app_client.search_asset(). The transaction in the returned result must be deserialized into a BBcTransaction object by using bbclib.recover_transaction_object_from_rawdata(). The returned result also includes the file itself.

### verify mode
verify_file() works in this mode. Similar to get mode, the file and the transaction are obtained using bbc_app_client.search_asset(). In the BBcEvent object of the returned transaction, BBcAsset includes the file digest value of the asset file, By calculating SHA-256 of the returned asset file, the integrity can be confirmed by comparing the file digest in the BBcAsset and the calculation resullt.

### send mode
enter_file_send_mode() works in this mode. The method includes 4 major steps as follows: preparation, creating a transaction, inserting the transaction into bbc_core and sending a message to the file receiver about completing the transfer process.

### receive mode
enter_file_wait_mode() works in this mode. The method includes 4 major steps as follows: preparation, waiting for a transaction in the sign request from the file sender, signing the transaction and returning it, and then, waiting for the complete message.

