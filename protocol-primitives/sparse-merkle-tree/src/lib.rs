pub const TREE_DEPTH: usize = 256;

/// Returns the bit at position `i` (0 = MSB, 255 = LSB)
pub fn get_bit(key: &[u8; 32], i: usize) -> u8 {
    let byte_index = i / 8;
    let bit_index = 7 - (i % 8);

    (key[byte_index] >> bit_index) & 1
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

        assert_eq!(get_bit(&key, 0), 1);    // MSB
        assert_eq!(get_bit(&key, 255), 1);  // LSB
    }

    #[test]
    fn test_get_bit_middle() {
        let mut key = [0u8; 32];

        // set bit 130 (arbitrary middle check)
        let i = 130;
        let byte_index = i / 8;
        let bit_index = 7 - (i % 8);

        key[byte_index] |= 1 << bit_index;

        assert_eq!(get_bit(&key, i), 1);
    }
}