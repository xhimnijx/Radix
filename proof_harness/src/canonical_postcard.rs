//! Compare a canonical postcard reserialization without allocating a second
//! proof-sized byte buffer.
//!
//! This operates only after deserialization; it does not bound allocations made
//! by postcard while constructing a proof object from untrusted nested vectors.

pub(crate) struct CanonicalBytes<'a> {
    expected: &'a [u8],
    offset: usize,
    matches: bool,
}

impl<'a> CanonicalBytes<'a> {
    pub(crate) fn new(expected: &'a [u8]) -> Self {
        Self {
            expected,
            offset: 0,
            matches: true,
        }
    }

    pub(crate) fn matches_exactly(&self) -> bool {
        self.matches && self.offset == self.expected.len()
    }
}

impl Extend<u8> for CanonicalBytes<'_> {
    fn extend<T: IntoIterator<Item = u8>>(&mut self, bytes: T) {
        for byte in bytes {
            if self.expected.get(self.offset) != Some(&byte) {
                self.matches = false;
            }
            self.offset = self.offset.saturating_add(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::CanonicalBytes;

    #[test]
    fn postcard_streaming_sink_matches_exact_reencoding() {
        let value = (0x1234_u32, vec![1_u8, 2, 3, 4]);
        let encoded = postcard::to_allocvec(&value).unwrap();

        let exact = postcard::to_extend(&value, CanonicalBytes::new(&encoded)).unwrap();
        assert!(exact.matches_exactly());

        let mut different = encoded.clone();
        different[0] ^= 1;
        let mismatch = postcard::to_extend(&value, CanonicalBytes::new(&different)).unwrap();
        assert!(!mismatch.matches_exactly());
    }
}
