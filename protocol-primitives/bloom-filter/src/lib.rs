use sha2::{Digest, Sha256};

pub struct BloomFilter {
    bits: Vec<bool>,
    size: usize,
    hash_functions: usize,
}

impl BloomFilter {
    pub fn new(size: usize, hash_functions: usize) -> Self {
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

    pub fn insert(&mut self, item: &str) {
        for i in 0..self.hash_functions {
            let index = self.hash(item, i);
            self.bits[index] = true;
        }
    }

    pub fn contains(&self, item: &str) -> bool {
        for i in 0..self.hash_functions {
            let index = self.hash(item, i);

            if !self.bits[index] {
                return false;
            }
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inserted_element_should_be_found() {
        let mut filter = BloomFilter::new(100, 3);

        filter.insert("transaction");

        assert!(filter.contains("transaction"));
    }

    #[test]
    fn non_inserted_element_should_usually_be_false() {
        let mut filter = BloomFilter::new(100, 3);

        filter.insert("tx1");

        assert!(!filter.contains("tx2"));
    }
}
