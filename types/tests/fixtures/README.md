The fixtures use v0.17.11 at commit
`4f3e42e3246025431bef5d77ceba1d55be0ebb77` and its locked dependencies.

`v0.17.11.json` contains Borsh transaction bytes, Bincode records, transaction
hashes, signatures, Merkle roots, and block hashes from the old code.
The transaction secret key contains 32 bytes with value 7.
The state records use transaction ID `[9; 32]`, height 29, and sequence ID 7.

`alphanet-v0.17.11.json` contains public seed blocks at heights 36 and 57.
The `get_block` and `list_stxos` responses supply the blocks and spent outputs.
The old code produced the Bincode body bytes and checked each Merkle root,
header hash, and signature.
