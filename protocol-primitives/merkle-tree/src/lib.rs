use sha2::{Digest, Sha256};

pub struct MerkleTree {
    leaves: Vec<Vec<u8>>,
    layers: Vec<Vec<Vec<u8>>>,
}

fn hash(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

impl MerkleTree {
    pub fn new(data: Vec<&[u8]>) -> Self {
        let leaves: Vec<Vec<u8>> = data.iter().map(|d| hash(d)).collect();

        let mut layers = Vec::new();
        layers.push(leaves.clone());

        let mut current = leaves;

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

        MerkleTree {
            leaves: layers[0].clone(),
            layers,
        }
    }

    pub fn root(&self) -> Vec<u8> {
        self.layers.last().unwrap()[0].clone()
    }

    pub fn proof(&self, mut index: usize) -> Vec<Vec<u8>> {
        let mut proof = Vec::new();

        for layer in &self.layers {
            if layer.len() == 1 {
                break;
            }

            let sibling = if index % 2 == 0 {
                index + 1
            } else {
                index - 1
            };

            if sibling < layer.len() {
                proof.push(layer[sibling].clone());
            }

            index /= 2;
        }

        proof
    }

    pub fn verify(
        leaf: &[u8],
        proof: Vec<Vec<u8>>,
        root: Vec<u8>,
        mut index: usize,
    ) -> bool {
        let mut hash_val = hash(leaf);

        for sibling in proof {
            let mut combined = if index % 2 == 0 {
                let mut c = hash_val.clone();
                c.extend(&sibling);
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

    #[test]
    fn merkle_proof_verification() {
        let data = vec![
            b"a".as_ref(),
            b"b".as_ref(),
            b"c".as_ref(),
            b"d".as_ref(),
        ];

        let tree = MerkleTree::new(data.clone());
        let proof = tree.proof(2);
        let root = tree.root();

        assert!(MerkleTree::verify(data[2], proof, root, 2));
    }
}
