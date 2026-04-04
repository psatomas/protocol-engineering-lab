use sha2::{Digest, Sha256};

fn hash(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

fn main() {
    let data = b"hello";
    let hashed = hash(data);

    println!("hash: {:?}", hashed);
}
