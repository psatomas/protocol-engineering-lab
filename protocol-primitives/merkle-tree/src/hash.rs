use sha2::{Digest, Sha256};

pub type Hash = [u8; 32];

fn finalize(hasher: Sha256) -> Hash {
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// Leaf hash: H(0x00 || data)
pub fn hash_leaf(data: &[u8]) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update([0x00]);
    hasher.update(data);
    finalize(hasher)
}

/// Node hash: H(0x01 || left || right)
pub fn hash_node(left: &Hash, right: &Hash) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update([0x01]);
    hasher.update(left);
    hasher.update(right);
    finalize(hasher)
}