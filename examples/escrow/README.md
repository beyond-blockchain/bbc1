Estate escrow
=============
The app consists of four scripts, which allow a user to do the following:
- land.py
    * Register the information of land, such as address and size, to the bbc_core
    * Transfer the owner of the land by updating the land information in bbc_core
- coin.py
    * Generate coin asset in bbc_core
    * Transfer coin owner in bbc_core
- LegalAffairsBureau.py
    * Check double spending of land by third-party (like a legal affairs bureau).
- escrow.py
    * Escrow land and coin to a third-party program (this script) to execute an atomic exchange between land and coin automatically.

This app uses two asset_groups (coin and land) in a domain. At an escrow transaction, escrow.py refers to each transaction in land/coin asset_group and links these assets to execute an escrow process.

## Files
user1 and user2 directories have the same scripts.

```
escrow/
├── README.md
├── LegalAffairsBureau.py   -- Check double spending when land transfer.
├── escrow.py               -- Escrow to this program and excange land and coin.
├── user1
│   ├── coin.py             -- Generate and send coin.
│   └── land.py             -- Regist land and change owner of land
└── user2
    ├── coin.py
    └── land.py
```

## How to Use
0. Start bbc_core.py in a terminal before using coin/land.py
    ```
    cd ../../core
    python bbc_core.py
    ```

### Land
1. Start LegalAffairsBureau.py in a terminal.
    ```
    python LegalAffairsBureau.py
    ```

2. Start land.py for land management in another terminal
    ```
    cd user1
    python land.py
    ```
    If a keypair (.private_key and .public_key) is not in the same directory as land.py, a new keypair is automatically created. A user has its own keypair, so if you want to get a land as another user, you need to make a new directory for the new user (like "user2" directory).

3. Run command
    ```
    Type command(help to see command list)
    >> help
    regist - regist land
    get - get land info
    chown - change owner of land
    exit - exit land manage
    ````
    You can see command list by "help" command.

4. Register land. Type "regist" command, and input the address of land you want to register.
    ```
    >> regist
    Type regist address
    >> hogehoge1-1
    ```
    This command invokes a transaction for registering land. In this transaction, the script requests signature to LegalAffairsBureau.py. After that, it inserts the transaction data to bbc_core and shows the result.

5. Transfer the ownership of land.
    ```
    >> chown
    Type AsID of land
    >> 011b8794bfbc860d9582fe471e2cd69f8ad656ee40d341b6b4a8783905856a0f
    get: b'{"owner": "d9547a840e8e2dd251494bf87a585e38a6978040a67c0c421253e64ee25f47f8", "place": "hogehoge1-1", "date": "1509162507"}'
    ref: []
    You want change owner of hogehoge1-1
    Type new owner ID
    >> 083b38b4efcba1f435f65742165733c99961ac26230f0e1d835328dae28fdee7
    ```
    When prompted, input the asset_id string of the land and the user_id string of the new owner.
    This command invokes a transaction for transferring the ownership of land. In this transaction, the script requests signature to LegalAffairsBureau.py, which checks double spending of the land by using "reference transaction." (If the reference transaction has been referenced before, it means that the land was transferred to another user before.) If the check is passed, the script inserts the transaction to bbc_core, and shows the result.

6. Get land info.
    Type "get" command to get the information of the land.
    ```
    >> get
    Type AsID of land
    >> ff22360cfc1c240bd7069eaf462bdd181b19b36e1a801f77bc74a8b2b7f72448
    get: b'{"owner": "083b38b4efcba1f435f65742165733c99961ac26230f0e1d835328dae28fdee7", "place": "hogehoge1-1", "date": "1509162889"}'
    ref: [<bbc1.common.bbclib.BBcReference object at 0x10e55d3c8>]
    ```

### Coin
1. Start coin.py for coin management in another terminal.
    ```
    cd user1
    python coin.py
    ```
    If a keypair (.private_key and .public_key) is not present in the same directory as coin.py, a new keypair is automatically created. This is the same case as in land.py.

3. Run command
    ```
    Type command(help to see command list)
    >> help
    generate - generate coin
    get - get coin info
    send - send coin
    recieve - wait for recieve coin
    exit - exit coin manage
    ````
    You can see command list by "help" command.


4. Generate coin
    ```
    >> generate
    Type price generate coin
    >> 1000
    ```
    When prompted, input the amount of coin you want to generate.
    This command invokes a transaction for generating a coin. The script inserts the transaction to bbc_core and show the result.

5. Send the coin to another user.
    ```
    >> send
    Type AsID of coin
    >> 7f07954e4142536037bb773a14748dc53ca93ef3ed10ddedec92a236c7dc8fcc
    get: b'{"owner": "d9547a840e8e2dd251494bf87a585e38a6978040a67c0c421253e64ee25f47f8", "price": "1000", "date": "1509163856"}'
    ref: []
    You want send coin(7f07954e4142536037bb773a14748dc53ca93ef3ed10ddedec92a236c7dc8fcc)
    Type new owner ID
    >> 083b38b4efcba1f435f65742165733c99961ac26230f0e1d835328dae28fdee7
    ```
    This command invokes a transaction for transferring the ownership of a coin. This script inserts the transaction to bbc_core and shows the result.

6. Get land info.
    ```
    >> get
    Type AsID of coin
    >> f05669720a506c6b34fc0fa573c6068625f08488397f802cb78fa85fa64a646f
    get: b'{"owner": "083b38b4efcba1f435f65742165733c99961ac26230f0e1d835328dae28fdee7", "price": "1000", "date": "1509164166"}'
    ref: [<bbc1.common.bbclib.BBcReference object at 0x10b5fd828>]
    ```

### Escrow
1. Start land.py and coin.py in each user's directory.
    * So, you need 4 terminal windows.

2. Make coin and land asset (use "regist" command in land.py, "generate" command in coin.py).

3. Start escrow.py in another terminal
    When prompted, input the asset_id of the land, two owner_ids and the price of the land.
    ```
    $python escrow.py
    welcome to sample escrow!
    Type AsID of land
    >>58899abd58f062afc9ba57b8054f299904a7ad8b872d1408beab00818f2d898d
    Type owner id of land
    >>d9547a840e8e2dd251494bf87a585e38a6978040a67c0c421253e64ee25f47f8
    Type price of land
    >>1000
    Type new owner ID of land
    >>b018cf97c578454a11613db1903c6eb6b04eb036dd8e263b20f0f89cc8257e9b
    New escrow is starting...
    escrow id: b'b4d1db0a8cf775ec36733b95453f03abb10d5cd744d3e3de9e8383af036e58ff'
    -------------------------
    {
        "price": "1000",
        "land": "58899abd58f062afc9ba57b8054f299904a7ad8b872d1408beab00818f2d898d",
        "place": "hogehoge1-1",
        "owner": "d9547a840e8e2dd251494bf87a585e38a6978040a67c0c421253e64ee25f47f8",
        "newowner": "b018cf97c578454a11613db1903c6eb6b04eb036dd8e263b20f0f89cc8257e9b",
        "coinstatus": "unspend",
        "landstatus": "unspend"
    }
    -------------------------
    Waiting land spend...
    Waiting coin spend...
    ```
    Then, wait for spending land and coin.

4. Each user sends land information or coin information to the escrow by using land.py and coin.py.
    * user_id of the escrow entity is show in escrow.py as "escrow id".
    * use "chown" command in land.py, "send" command in coin.py (you should have run them in the terminals prepared in step 1)

5. When the escrow gets the land and the coin, escrow.py automatically invokes a transaction to send coin to land owner, and to transfer the ownership to the new land owner.
