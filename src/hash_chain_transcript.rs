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
pub fn keccak256(input: &[u8], dest: &mut [u8]) {
    let mut hasher = Keccak::v256();
    hasher.update(input.as_ref());
    hasher.finalize(dest);
}

/// Pad a label to 32 bytes in a manner consistent with Cairo.
/// Panics if the label is longer than 32 bytes.
pub fn pad_label(label: &[u8]) -> [u8; 32] {
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
    padded_label
        .iter()
        .rev()
        .cloned()
        .collect::<Vec<u8>>()
        .try_into()
        .unwrap()
}

#[derive(Clone)]
pub struct HashChainTranscript {
    state: [u8; 32],
}

impl HashChainTranscript {
    /// Create a new instance of a transcript, seeded with the given `label`
    pub fn new(label: &'static [u8]) -> Self {
        let mut state = [0u8; 32];

        keccak256(&pad_label(label), &mut state);
        HashChainTranscript { state }
    }

    /// Absorb a message into the transcript state
    pub fn append_message(&mut self, label: &'static [u8], message: &[u8]) {
        let data: Vec<u8> = message
            .iter()
            .chain(pad_label(label).iter())
            .chain(self.state.iter())
            .cloned()
            .collect();

        keccak256(&data, self.state.as_mut());
    }

    /// Absorb a u64 into the transcript state
    pub fn append_u64(&mut self, label: &'static [u8], x: u64) {
        self.append_message(label, &encode_u64_as_u256_le(x));
    }

    /// Squeeze 32 challenge bytes out of the transcript state
    pub fn challenge_bytes(&mut self, label: &'static [u8], dest: &mut [u8]) {
        let data: Vec<u8> = pad_label(label)
            .iter()
            .chain(self.state.iter())
            .cloned()
            .collect();

        let mut output = [0u8; 32];
        keccak256(&data, &mut output);

        self.state.copy_from_slice(&output);
        dest.copy_from_slice(&output);
    }

    /// Fork the current [`HashChainTranscript`] to construct an RNG whose output is bound
    /// to the current transcript state as well as prover's secrets.
    pub fn build_rng(&self) -> HashChainTranscriptRngBuilder {
        HashChainTranscriptRngBuilder {
            transcript: self.clone(),
        }
    }
}

pub struct HashChainTranscriptRngBuilder {
    transcript: HashChainTranscript,
}

impl HashChainTranscriptRngBuilder {
    /// Rekey the transcript using the provided witness data.
    ///
    /// The `label` parameter is metadata about `witness`.
    pub fn rekey_with_witness_bytes(
        mut self,
        label: &'static [u8],
        witness: &[u8],
    ) -> HashChainTranscriptRngBuilder {
        self.transcript.append_message(label, witness);
        self
    }

    /// Use the supplied external `rng` to rekey the transcript, so
    /// that the finalized [`TranscriptRng`] is a PRF bound to
    /// randomness from the external RNG, as well as all other
    /// transcript data.
    pub fn finalize<R>(mut self, rng: &mut R) -> HashChainTranscriptRng
    where
        R: rand_core::RngCore + rand_core::CryptoRng,
    {
        let random_bytes = {
            let mut bytes = [0u8; 32];
            rng.fill_bytes(&mut bytes);
            bytes
        };

        self.transcript.append_message(b"rng", &random_bytes);

        HashChainTranscriptRng {
            transcript: self.transcript,
        }
    }
}

pub struct HashChainTranscriptRng {
    transcript: HashChainTranscript,
}

impl rand_core::RngCore for HashChainTranscriptRng {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0_u8; 32];
        self.transcript.challenge_bytes(b"next_u32", &mut bytes);
        u32::from_le_bytes(bytes[0..4].try_into().unwrap())
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0_u8; 32];
        self.transcript.challenge_bytes(b"next_u64", &mut bytes);
        u64::from_le_bytes(bytes[0..8].try_into().unwrap())
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        rand_core::impls::fill_bytes_via_next(self, dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl rand_core::CryptoRng for HashChainTranscriptRng {}
