The fixtures use v0.17.11 at commit
`4f3e42e3246025431bef5d77ceba1d55be0ebb77` and its locked dependencies.

`v0.17.11.json` contains Borsh transaction bytes, Bincode records, transaction
hashes, signatures, Merkle roots, and block hashes from the old code.
The transaction secret key contains 32 bytes with value 7.
The state records use transaction ID `[9; 32]`, height 29, and sequence ID 7.

The block level fixtures went away with the coinbase memo and the coinbase
txid outpoints. Those changed every body byte, Merkle root, and block hash.
The transaction level fixtures still hold.
