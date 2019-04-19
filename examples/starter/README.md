Starter example
====

This directory includes an simple example of BBc-1 application. The goal of this example is to show how BBc-1 Transaction is created/treated in an application. The scripts in this directory are helper tools to build up an envilonment of BBc-1 system (configure and run bbc\_core) and to create an user and to run client app.

# How to use

### Step 1. Install modules (Run just once)

```bash
bash ./starter.sh install 
```

Note that python3 virtualenv is required to build the environment.


### Step 2. Setup initial configuration of bbc_core.py (Run just once)

```bash
bash ./starter.sh setup 
```


### Step 3. Run bbc_core in background

If you have not run bbc_core.py, run it as follows:

```bash
bash ./starter.sh core 
```


### Step 4. Create a user

```bash
bash ./starter.sh create *username* 
```

You can specify *username* as you like. Then, you will find the directory whose name is the specified user name.

### Step 5. Generate and register a transaction

Suppose that you created UserA in the previous step.

Enter directory "UserA" and run the script as follows:

```bash
cd UserA
bash ./run_script.sh register
```

You can run the above script multiple times, then multiple transactions are registered.
The script invokes register_a_transaction.py, which finds the latest transaction of the user (the user of the asset in the transaction equals to the user_id described in ID_FILE.) The new transaction has BBcPointer pointing to the latest transaction_id.

### Step 6. Show the user's transactions

Enter directory "UserA" and run the script as follows:
```bash
cd UserA
bash ./run_script.sh show_all
```

You will see the summary information of the registered transactions of the user.

### Step 7. Dump a transaction

You can print the content of a transaction by specifying a transaction_id.

```bash
cd UserA
bash ./run_script.sh print *transaction_id*
```
\*transaction_id\* is in a hex format like "cb2e83022c32a25a565b90de89735b7e14c02ec6b3ce8ecc7ffb36254a2bcd96".


# Other options

### Kill bbc_core.py process

```bash
bash ./starter.sh kill 
```


### Clean up all data

```bash
bash ./starter.sh clean
```

You have to setup bbc_core configuration again. (see step.2)

### Remove a user

```bash
bash ./starter.sh remove *username* 
```

The directory of the specified username will be removed.
