Payment
==========
This app allows a user to do the following:
* define and change users
* define and switch among currencies
* create currency tokens for a user
* delete currency tokens
* transfer currency tokens from the user to another user
* show proof of existence of tokens
* show status (balances, etc.) of currencies

# How to use
1. Start bbc_core.py in a terminal
    ```
    cd ../../bbc1/core
    python bbc_core.py
    ```
2. Create a super user (issuer), a domain and an asset group.
    ```
    python payment.py setup
    ```
   User name "super" is reserved for the super user.
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
        python payment.py def-currency [name]
        ```
    * Show currencies
        ```
        python payment.py currency
        ```
    * Switch to a currency
        ```
        python payment.py currency [name]
        ```
    * Transfer the currency tokens to a user
        ```
        python payment.py transfer [amount] [username]
        ```
      If this is performed by the super user, currency tokens are created.
      If this is performed against the super user, the tokens are returned
      and destroyed.
5. Status commands
    * Show the currency status
        ```
        python payment.py status
        ```
    * Show the currency status for a user
        ```
        python payment.py status [username]
        ```
    * Show the proof of possession for a user
        ```
        python payment.py proof [username]
        ```

