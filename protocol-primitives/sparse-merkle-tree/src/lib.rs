use sha2::{Digest, Sha256};
use std::collections::HashMap;

pub const TREE_DEPTH: usize = 256;

pub type Hash = [u8; 32];

/// Returns the bit at position `i` (0 = MSB, 255 = LSB)
pub fn get_bit(key: &[u8; 32], i: usize) -> u8 {
    let byte_index = i / 8;
    let bit_index = 7 - (i % 8);

    (key[byte_index] >> bit_index) & 1
}

const LEAF_PREFIX: u8 = 0x00;

pub fn hash_leaf(value: &[u8; 32]) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update([LEAF_PREFIX]); // domain separation
    hasher.update(value);

    hasher.finalize().into()
}

pub fn empty_leaf() -> Hash {
    hash_leaf(&[0u8; 32])
}

const NODE_PREFIX: u8 = 0x01;

pub fn hash_node(left: &Hash, right: &Hash) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update([NODE_PREFIX]); // domain separation
    hasher.update(left);
    hasher.update(right);

    hasher.finalize().into()
}

pub fn build_zero_hashes() -> [Hash; TREE_DEPTH + 1] {
    let mut hashes = [[0u8; 32]; TREE_DEPTH + 1];

    hashes[0] = empty_leaf();

    for i in 1..=TREE_DEPTH {
        hashes[i] = hash_node(&hashes[i - 1], &hashes[i - 1]);
    }

    hashes
}

pub struct SparseMerkleTree {
    // FIXED: use (level, key) instead of (level, hash)
    pub nodes: HashMap<(usize, [u8; 32]), Hash>,
    pub root: Hash,
    pub zero_hashes: [Hash; TREE_DEPTH + 1],
}

impl SparseMerkleTree {
    pub fn new() -> Self {
        let zero_hashes = build_zero_hashes();

        Self {
            nodes: HashMap::new(),
            root: zero_hashes[TREE_DEPTH],
            zero_hashes,
        }
    }

    pub fn update(&mut self, _key: Hash, _value: Hash) {
        unimplemented!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_bit_msb_lsb() {
        let mut key = [0u8; 32];

        // MSB of byte 0
        key[0] = 0b1000_0000;

        // LSB of full 256-bit array
        key[31] = 0b0000_0001;

        assert_eq!(get_bit(&key, 0), 1); // MSB
        assert_eq!(get_bit(&key, 255), 1); // LSB
    }

    #[test]
    fn test_get_bit_middle() {
        let mut key = [0u8; 32];

        let i = 130;
        let byte_index = i / 8;
        let bit_index = 7 - (i % 8);

        key[byte_index] |= 1 << bit_index;

        assert_eq!(get_bit(&key, i), 1);
    }

    #[test]
    fn test_hash_node_deterministic() {
        let a = [1u8; 32];
        let b = [2u8; 32];

        let h1 = hash_node(&a, &b);
        let h2 = hash_node(&a, &b);

        assert_eq!(h1, h2);
    }

    #[test]
    fn test_hash_node_order_matters() {
        let a = [1u8; 32];
        let b = [2u8; 32];

        let h1 = hash_node(&a, &b);
        let h2 = hash_node(&b, &a);

        assert_ne!(h1, h2);
    }

    #[test]
    fn test_zero_hashes_structure() {
        let z = build_zero_hashes();

        let z2 = build_zero_hashes();
        assert_eq!(z, z2);

        assert_ne!(z[0], z[1]);
    }

    #[test]
    fn test_zero_hash_base_is_leaf() {
        let z = build_zero_hashes();

        assert_eq!(z[0], empty_leaf());
    }

    #[test]
    fn test_new_tree_root_is_zero() {
        let tree = SparseMerkleTree::new();

        assert_eq!(tree.root, tree.zero_hashes[TREE_DEPTH]);
    }
}
