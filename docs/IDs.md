Identifiers in BBc-1
====================
In BBc-1, various kinds of identifiers are defined. All of them are 256-bit value (basically calculated by SHA-256 or now).

* transaction_id
    - ID of a transaction data
* asset_id
    - ID of an asset
        - If the asset is in a storage as a file, the file name is the asset_id.
* asset_group_id
    - ID of an asset group
* domain_id
    - ID of a domain
        - A domain corresponds to a set of bbc_nodes where transaction data and asset files are shared.
        - A bbc_node can accommodate any number of domains.
        - An application can use one or more domains and several applications can use a single domain.
* user_id
    - ID of a user (or an user of a asset)
        - A user_id is also used as a destination and a source to exchange messages between application users.
* node_id
    - ID of a bbc_node
        - A node_id is used as a destination and a source to exchange messages between bbc_nodes.

## Uniqueness
A name space is defined in a single asset_group. So, each ID such as user_id, asset_id and transaction_id, must be unique in the asset_group.
As for node_id, it must be unique in a domain.
An asset_group_id and a domain_id must be unique globally if the domain connects to domain_global_0. If the domain is completely isolated from the domain_global_0, they must be unique within the isolated world.

