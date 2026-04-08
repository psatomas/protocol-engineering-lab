use sha2::{Digest, Sha256};

/// Trait for types that can be hashed and used as MerkleTree leaves
pub trait Hashable {
    fn hash(&self) -> Vec<u8>;
}

/// Utility function for SHA256 hashing
fn hash(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// Generic MerkleTree struct
pub struct MerkleTree<T: Hashable> {
    pub leaves: Vec<T>,
    layers: Vec<Vec<Vec<u8>>>, // internal hashed layers
}

impl<T: Hashable> MerkleTree<T> {
    /// Create a new MerkleTree from a vector of leaves
    pub fn new(leaves: Vec<T>) -> Self {
        // Hash leaves
        let hashed_leaves: Vec<Vec<u8>> = leaves.iter().map(|l| l.hash()).collect();

        let mut layers = Vec::new();
        layers.push(hashed_leaves.clone());

        let mut current = hashed_leaves;

        while current.len() > 1 {
            let mut next_layer = Vec::new();

            for pair in current.chunks(2) {
                if pair.len() == 2 {
                    let mut combined = pair[0].clone();
                    combined.extend(&pair[1]);
                    next_layer.push(hash(&combined));
                } else {
                    next_layer.push(pair[0].clone());
                }
            }

            layers.push(next_layer.clone());
            current = next_layer;
        }

        MerkleTree { leaves, layers }
    }

    /// Return the root of the MerkleTree
    pub fn root(&self) -> Vec<u8> {
        self.layers.last().unwrap()[0].clone()
    }

    /// Generate a Merkle proof for a given leaf index
    pub fn proof(&self, mut index: usize) -> Vec<Vec<u8>> {
        let mut proof = Vec::new();

        for layer in &self.layers {
            if layer.len() == 1 {
                break;
            }

            let sibling = if index % 2 == 0 { index + 1 } else { index - 1 };

            if sibling < layer.len() {
                proof.push(layer[sibling].clone());
            }

            index /= 2;
        }

        proof
    }

    /// Verify a Merkle proof for a leaf against a root
    pub fn verify(leaf: &T, proof: &[Vec<u8>], root: &[u8], mut index: usize) -> bool {
        let mut hash_val = leaf.hash();

        for sibling in proof {
            let combined = if index % 2 == 0 {
                let mut c = hash_val.clone();
                c.extend(sibling);
                c
            } else {
                let mut c = sibling.clone();
                c.extend(&hash_val);
                c
            };

            hash_val = hash(&combined);
            index /= 2;
        }

        hash_val == root
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Implement Hashable for Vec<u8> for testing
    impl Hashable for Vec<u8> {
        fn hash(&self) -> Vec<u8> {
            let mut hasher = Sha256::new();
            hasher.update(self);
            hasher.finalize().to_vec()
        }
    }

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
