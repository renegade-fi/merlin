//! A simple Fiat-Shamir transcript that uses a Keccak256 hash chain.

use byteorder::{ByteOrder, LittleEndian};
use std::convert::TryInto;
use tiny_keccak::{Hasher, Keccak};

/// Encode a u64 as a little-endian "u256", i.e. a 32-byte array
fn encode_u64_as_u256_le(x: u64) -> [u8; 32] {
    let mut buf = [0; 32];
    LittleEndian::write_u64(&mut buf, x);

    buf
}

/// Compute the Keccak256 hash of `input` and write it to `dest`
fn keccak256(input: &[u8], dest: &mut [u8]) {
    let mut hasher = Keccak::v256();
    hasher.update(input.as_ref());
    hasher.finalize(dest);
}

pub struct HashChainTranscript {
    pub state: [u8; 32],
}

impl HashChainTranscript {
    /// Create a new instance of a transcript, seeded with the given `label`
    pub fn new(label: &'static [u8]) -> Self {
        let mut state = [0u8; 32];

        keccak256(&HashChainTranscript::pad_label(label), &mut state);
        HashChainTranscript { state }
    }

    /// Absorb a message into the transcript state
    pub fn append_message(&mut self, label: &'static [u8], message: &[u8]) {
        let data: Vec<u8> = message
            .iter()
            .chain(HashChainTranscript::pad_label(label).iter())
            .chain(self.state.iter())
            .cloned()
            .collect();

        keccak256(&data, self.state.as_mut());
    }

    /// Absorb a u64 into the transcript state
    pub fn append_u64(&mut self, label: &'static [u8], x: u64) {
        self.append_message(label, &encode_u64_as_u256_le(x));
    }

    /// Squeeze challenge bytes out of the transcript state
    pub fn challenge_bytes(&mut self, label: &'static [u8], dest: &mut [u8]) {
        let data: Vec<u8> = HashChainTranscript::pad_label(label)
            .iter()
            .chain(self.state.iter())
            .cloned()
            .collect();

        keccak256(&data, self.state.as_mut());

        keccak256(&self.state, dest)
    }

    /// Pad a label to 32 bytes in a manner consistent with Cairo.
    /// Panics if the label is longer than 32 bytes.
    fn pad_label(label: &'static [u8]) -> [u8; 32] {
        // In Cairo, the label is stored as a big-endian u256, but is read
        // into the Keccak hash function in little-endian (i.e., reverse) byte order.
        // This function replicates that by left-padding the label w/ zeros
        // (preserving its value as a big-endian u256), then reversing the bytes.
        assert!(
            label.len() <= 32,
            "Label must be less than or equal to 32 bytes",
        );
        let mut padded_label = [0u8; 32];
        padded_label[32 - label.len()..].copy_from_slice(label);
        padded_label = padded_label
            .iter()
            .rev()
            .cloned()
            .collect::<Vec<u8>>()
            .try_into()
            .unwrap();
        padded_label
    }
}
