use sha2::{Digest, Sha256};

/// Fixed-size hash type
pub type Hash = [u8; 32];

/// Trait for types that can be hashed as Merkle leaves
pub trait Hashable {
    fn hash(&self) -> Hash;
}

/// SHA256 helper
fn sha256(data: &[u8]) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(data);

    let result = hasher.finalize();

    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// Domain-separated leaf hash: H(0x00 || data)
fn hash_leaf(data: &[u8]) -> Hash {
    let mut prefixed = Vec::with_capacity(1 + data.len());
    prefixed.push(0x00);
    prefixed.extend_from_slice(data);

    sha256(&prefixed)
}

/// Domain-separated node hash: H(0x01 || left || right)
fn hash_node(left: &Hash, right: &Hash) -> Hash {
    let mut combined = [0u8; 65];

    combined[0] = 0x01;
    combined[1..33].copy_from_slice(left);
    combined[33..].copy_from_slice(right);

    sha256(&combined)
}

/// Implement Hashable for byte slices
impl Hashable for &[u8] {
    fn hash(&self) -> Hash {
        hash_leaf(self)
    }
}

/// Implement Hashable for Vec<u8>
impl Hashable for Vec<u8> {
    fn hash(&self) -> Hash {
        hash_leaf(self)
    }
}

/// Generic MerkleTree struct
pub struct MerkleTree<T: Hashable> {
    pub leaves: Vec<T>,
    layers: Vec<Vec<Hash>>,
}

impl<T: Hashable> MerkleTree<T> {
    /// Create a new Merkle tree
    pub fn new(leaves: Vec<T>) -> Self {
        let hashed_leaves: Vec<Hash> = leaves.iter().map(|l| l.hash()).collect();

        let mut layers = Vec::new();
        layers.push(hashed_leaves.clone());

        let mut current = hashed_leaves;

        while current.len() > 1 {
            let mut next_layer = Vec::new();

            for pair in current.chunks(2) {
                if pair.len() == 2 {
                    next_layer.push(hash_node(&pair[0], &pair[1]));
                } else {
                    next_layer.push(pair[0]);
                }
            }

            layers.push(next_layer.clone());
            current = next_layer;
        }

        MerkleTree { leaves, layers }
    }

    /// Return Merkle root
    pub fn root(&self) -> Hash {
        self.layers.last().unwrap()[0]
    }

    /// Generate proof for a leaf index
    pub fn proof(&self, mut index: usize) -> Vec<Hash> {
        let mut proof = Vec::new();

        for layer in &self.layers {
            if layer.len() == 1 {
                break;
            }

            let sibling = if index % 2 == 0 { index + 1 } else { index - 1 };

            if sibling < layer.len() {
                proof.push(layer[sibling]);
            }

            index /= 2;
        }

        proof
    }

    /// Verify proof
    pub fn verify(leaf: &T, proof: &[Hash], root: &Hash, mut index: usize) -> bool {
        let mut hash_val = leaf.hash();

        for sibling in proof {
            hash_val = if index % 2 == 0 {
                hash_node(&hash_val, sibling)
            } else {
                hash_node(sibling, &hash_val)
            };

            index /= 2;
        }

        &hash_val == root
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merkle_proof_verification() {
        let data: Vec<Vec<u8>> = vec![
            b"a".to_vec(),
            b"b".to_vec(),
            b"c".to_vec(),
            b"d".to_vec(),
        ];

        let tree = MerkleTree::new(data.clone());

        let proof = tree.proof(2);
        let root = tree.root();

        assert!(MerkleTree::verify(&data[2], &proof, &root, 2));
    }

    #[test]
    fn domain_separation_works() {
        let leaf = hash_leaf(b"abc");
        let node = hash_node(&leaf, &leaf);

        assert_ne!(leaf, node);
    }
}