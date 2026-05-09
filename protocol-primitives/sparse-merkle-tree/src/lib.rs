use sha2::{Digest, Sha256};
use std::collections::HashMap;

pub const TREE_DEPTH: usize = 256;

pub type Hash = [u8; 32];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NodeKey {
    pub depth: usize,
    pub prefix: Hash,
}

/// Returns the bit at position `i` (0 = MSB, 255 = LSB)
pub fn get_bit(key: &[u8; 32], i: usize) -> u8 {
    let byte_index = i / 8;
    let bit_index = 7 - (i % 8);

    (key[byte_index] >> bit_index) & 1
}

pub fn prefix(key: &Hash, depth: usize) -> Hash {
    assert!(depth <= 256);

    let mut out = [0u8; 32];

    let full_bytes = depth / 8;
    let remaining_bits = depth % 8;

    // Preserve fully covered bytes
    out[..full_bytes].copy_from_slice(&key[..full_bytes]);

    // Preserve partial byte bits (MSB-first)
    if remaining_bits > 0 {
        let mask = 0xFF << (8 - remaining_bits);
        out[full_bytes] = key[full_bytes] & mask;
    }

    out
}

pub fn sibling_prefix(prefix: &Hash, depth: usize) -> Hash {
    assert!(depth < 256);

    let mut out = *prefix;

    let byte = depth / 8;
    let bit = 7 - (depth % 8);

    out[byte] ^= 1 << bit;

    out
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
    pub nodes: HashMap<NodeKey, Hash>,
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

    pub fn update(&mut self, key: Hash, value: Hash) {
        // level 0
        let mut current = hash_leaf(&value);

        self.nodes.insert(
            NodeKey {
                depth: 0,
                prefix: prefix(&key, TREE_DEPTH),
            },
            current,
        );

        for level in 0..TREE_DEPTH {
            let bit = get_bit(&key, TREE_DEPTH - level - 1);

            let current_prefix = prefix(&key, TREE_DEPTH - level);

            let sibling_prefix = {
                let mut p = current_prefix;

                let bit_pos = TREE_DEPTH - level - 1;

                let byte_index = bit_pos / 8;
                let bit_index = 7 - (bit_pos % 8);

                p[byte_index] ^= 1 << bit_index;

                p
            };

            let sibling = self
                .nodes
                .get(&NodeKey {
                    depth: level,
                    prefix: sibling_prefix,
                })
                .copied()
                .unwrap_or(self.zero_hashes[level]);

            let (left, right) = if bit == 0 {
                (current, sibling)
            } else {
                (sibling, current)
            };

            let parent = hash_node(&left, &right);

            self.nodes.insert(
                NodeKey {
                    depth: level + 1,
                    prefix: prefix(&key, TREE_DEPTH - (level + 1)),
                },
                parent,
            );
            current = parent;
        }

        self.root = current;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_bit_msb_lsb() {
        let mut key = [0u8; 32];

        key[0] = 0b1000_0000; // MSB
        key[31] = 0b0000_0001; // LSB

        assert_eq!(get_bit(&key, 0), 1);
        assert_eq!(get_bit(&key, 255), 1);
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

    #[test]
    fn test_insert_leaf() {
        let mut tree = SparseMerkleTree::new();

        let key = [1u8; 32];
        let value = [2u8; 32];

        tree.update(key, value);

        let stored = tree.nodes.get(&(0, key)).unwrap();
        assert_eq!(*stored, hash_leaf(&value));
    }

    #[test]
    fn test_parent_level_1() {
        let mut tree = SparseMerkleTree::new();

        let key = [0u8; 32]; // ensures predictable bit = 0
        let value = [5u8; 32];

        tree.update(key, value);

        let leaf = hash_leaf(&value);
        let sibling = tree.zero_hashes[0];
        let expected = hash_node(&leaf, &sibling);

        let stored = tree.nodes.get(&(1, key)).unwrap();
        assert_eq!(*stored, expected);
    }

    #[test]
    fn test_update_changes_root() {
        let mut tree = SparseMerkleTree::new();

        let initial_root = tree.root;

        tree.update([1u8; 32], [2u8; 32]);

        assert_ne!(tree.root, initial_root);
    }

    #[test]
    fn test_same_update_same_root() {
        let mut tree1 = SparseMerkleTree::new();
        let mut tree2 = SparseMerkleTree::new();

        let key = [7u8; 32];
        let value = [9u8; 32];

        tree1.update(key, value);
        tree2.update(key, value);

        assert_eq!(tree1.root, tree2.root);
    }

    #[test]
    fn test_two_leaves_same_order_same_root() {
        let mut tree1 = SparseMerkleTree::new();
        let mut tree2 = SparseMerkleTree::new();

        tree1.update([1u8; 32], [10u8; 32]);
        tree1.update([2u8; 32], [20u8; 32]);

        tree2.update([1u8; 32], [10u8; 32]);
        tree2.update([2u8; 32], [20u8; 32]);

        assert_eq!(tree1.root, tree2.root);
    }

    #[test]
    fn test_insertion_order_independent() {
        let mut tree1 = SparseMerkleTree::new();
        let mut tree2 = SparseMerkleTree::new();

        tree1.update([1u8; 32], [10u8; 32]);
        tree1.update([2u8; 32], [20u8; 32]);

        tree2.update([2u8; 32], [20u8; 32]);
        tree2.update([1u8; 32], [10u8; 32]);

        assert_eq!(tree1.root, tree2.root);
    }

    #[test]
    fn test_overwrite_leaf_changes_root() {
        let mut tree = SparseMerkleTree::new();

        let key = [42u8; 32];

        tree.update(key, [1u8; 32]);
        let root1 = tree.root;

        tree.update(key, [2u8; 32]);
        let root2 = tree.root;

        assert_ne!(root1, root2);
    }

    #[test]
    fn test_prefix_depth_0() {
        let key = [255u8; 32];

        assert_eq!(prefix(&key, 0), [0u8; 32]);
    }

    #[test]
    fn test_prefix_partial_bits() {
        let key = [0b10110000u8; 32];

        let p = prefix(&key, 3);

        assert_eq!(p[0], 0b10100000);
    }
}
