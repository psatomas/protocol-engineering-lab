use sha2::{Digest, Sha256};

/// Fixed-size hash type
pub type Hash = [u8; 32];

/// Trait for types that can be hashed as Merkle leaves
pub trait Hashable {
    fn hash(&self) -> Hash;
}

/// SHA256 helper returning fixed-size hash
fn sha256(data: &[u8]) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(data);

    let result = hasher.finalize();

    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);

    hash
}

/// Implement Hashable for byte slices
impl Hashable for &[u8] {
    fn hash(&self) -> Hash {
        sha256(self)
    }
}

/// Implement Hashable for Vec<u8>
impl Hashable for Vec<u8> {
    fn hash(&self) -> Hash {
        sha256(self)
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
                    let mut combined = [0u8; 64];
                    combined[..32].copy_from_slice(&pair[0]);
                    combined[32..].copy_from_slice(&pair[1]);

                    next_layer.push(sha256(&combined));
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
            let mut combined = [0u8; 64];

            if index % 2 == 0 {
                combined[..32].copy_from_slice(&hash_val);
                combined[32..].copy_from_slice(sibling);
            } else {
                combined[..32].copy_from_slice(sibling);
                combined[32..].copy_from_slice(&hash_val);
            }

            hash_val = sha256(&combined);
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
}
