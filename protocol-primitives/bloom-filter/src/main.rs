use sha2::{Digest, Sha256};

struct BloomFilter {
    bits: Vec<bool>,
    size: usize,
    hash_functions: usize,
}

impl BloomFilter {
    fn new(size: usize, hash_functions: usize) -> Self {
        BloomFilter {
            bits: vec![false; size],
            size,
            hash_functions,
        }
    }

    fn hash(&self, item: &str, seed: usize) -> usize {
        let mut hasher = Sha256::new();
        hasher.update(item.as_bytes());
        hasher.update(seed.to_le_bytes());
        let result = hasher.finalize();

        let mut num = 0usize;
        for byte in result.iter().take(8) {
            num = (num << 8) | (*byte as usize);
        }

        num % self.size
    }

    fn insert(&mut self, item: &str) {
        for i in 0..self.hash_functions {
            let index = self.hash(item, i);
            self.bits[index] = true;
        }
    }

    fn contains(&self, item: &str) -> bool {
        for i in 0..self.hash_functions {
            let index = self.hash(item, i);

            if !self.bits[index] {
                return false;
            }
        }

        true
    }
}

fn main() {
    let mut filter = BloomFilter::new(1000, 3);

    filter.insert("tx1");
    filter.insert("tx2");

    println!("tx1: {}", filter.contains("tx1"));
    println!("tx3: {}", filter.contains("tx3"));
}
