# Merkle Tree Notes

A Merkle Tree is a cryptographic data structure that allows
efficient and secure verification of data inclusion.

Each leaf node is a hash of a data block.
Parent nodes are hashes of their children.

Properties:

- O(log n) proof size
- tamper detection
- deterministic root

Blockchain usage:

Bitcoin:
- transactions inside a block are hashed into a Merkle tree
- the root is stored in the block header

Ethereum:
- used in modified Patricia Merkle trees for state storage

Why this matters:

Merkle proofs allow light clients to verify transactions
without downloading the entire block.