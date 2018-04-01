Payment
==========
This app allows a user to do the following:
* define and switch among users
* define and switch among currencies
* create currency tokens for a user
* delete currency tokens
* transfer currency tokens from the user to another user
* show status (balances, etc.) of currencies

# How to use
1. Start bbc_core.py in a terminal
    ```
    cd ../../bbc1/core
    python bbc_core.py
    ```
2. Create a domain.
    ```
    python payment.py setup
    ```
3. User commands
    * Define a user
        ```
        python payment.py def-user [username]
        ```
    * Show users
        ```
        python payment.py user
        ```
    * Switch to a user
        ```
        python payment.py user [username]
        ```
    * Replace the key-pair for a user
        ```
        python payment.py new-keypair [username]
        ```
4. Currency commands
    * Define a currency
        ```
        python payment.py def-currency [name] [symbol] [file]
        ```
      where file contains a definition in JSON.
    * Show currencies
        ```
        python payment.py currency
        ```
    * Switch to a currency
        ```
        python payment.py currency [name]
        ```
    * Issue currency tokens to a user
        ```
        python payment.py issue [amount] [username]
        ```
    * Transfer the currency tokens to a user
        ```
        python payment.py transfer [amount] [username]
        ```
      
5. Status commands
    * Show the currency status (not implemented yet)
        ```
        python payment.py status
        ```
    * Show the currency status for a user
        ```
        python payment.py status [username]
        ```
