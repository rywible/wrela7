//! Self-contained SHA-256 used for declared compiler and toolchain inputs.
//!
//! Keeping this implementation in the package-loading capability crate avoids
//! platform crypto providers and ambient configuration. It implements FIPS
//! 180-4 SHA-256 and retains no global mutable state.

use wrela_build_model::Sha256Digest;

use super::{ContentDigest, ContentHasher};

const INITIAL_STATE: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

const ROUND_CONSTANTS: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

/// Deterministic software SHA-256 capability.
#[derive(Debug, Default, Clone, Copy)]
pub struct SoftwareSha256;

impl ContentHasher for SoftwareSha256 {
    fn sha256(&self, bytes: &[u8]) -> Sha256Digest {
        let mut digest = SoftwareSha256State::new();
        digest.update_bytes(bytes);
        digest.finalize()
    }

    fn begin_sha256(&self) -> Box<dyn ContentDigest + '_> {
        Box::new(SoftwareSha256State::new())
    }
}

struct SoftwareSha256State {
    state: [u32; 8],
    buffer: [u8; 64],
    buffer_len: usize,
    total_bytes: u128,
}

impl SoftwareSha256State {
    const fn new() -> Self {
        Self {
            state: INITIAL_STATE,
            buffer: [0; 64],
            buffer_len: 0,
            total_bytes: 0,
        }
    }

    fn update_bytes(&mut self, mut bytes: &[u8]) {
        // A Rust slice cannot itself exceed `usize::MAX`; u128 leaves ample
        // room for every bounded compiler update sequence without overflow.
        self.total_bytes = self.total_bytes.saturating_add(bytes.len() as u128);

        if self.buffer_len != 0 {
            let available = 64 - self.buffer_len;
            let take = available.min(bytes.len());
            let end = self.buffer_len + take;
            self.buffer[self.buffer_len..end].copy_from_slice(&bytes[..take]);
            self.buffer_len = end;
            bytes = &bytes[take..];
            if self.buffer_len == 64 {
                let block = self.buffer;
                self.compress(&block);
                self.buffer_len = 0;
            }
        }

        while bytes.len() >= 64 {
            let (block, rest) = bytes.split_at(64);
            let mut fixed = [0u8; 64];
            fixed.copy_from_slice(block);
            self.compress(&fixed);
            bytes = rest;
        }

        if !bytes.is_empty() {
            self.buffer[..bytes.len()].copy_from_slice(bytes);
            self.buffer_len = bytes.len();
        }
    }

    fn finalize(mut self) -> Sha256Digest {
        // FIPS 180-4 messages are shorter than 2^64 bits. Compiler-controlled
        // input policies are many orders of magnitude below this ceiling. The
        // low 64 bits keep finalization total even if an out-of-contract host
        // calls the incremental capability beyond that domain.
        let bit_length = self.total_bytes.wrapping_mul(8) as u64;
        self.buffer[self.buffer_len] = 0x80;
        self.buffer_len += 1;
        if self.buffer_len > 56 {
            self.buffer[self.buffer_len..].fill(0);
            let block = self.buffer;
            self.compress(&block);
            self.buffer = [0; 64];
            self.buffer_len = 0;
        }
        self.buffer[self.buffer_len..56].fill(0);
        self.buffer[56..64].copy_from_slice(&bit_length.to_be_bytes());
        let block = self.buffer;
        self.compress(&block);

        let mut bytes = [0u8; 32];
        for (word, destination) in self.state.iter().zip(bytes.chunks_exact_mut(4)) {
            destination.copy_from_slice(&word.to_be_bytes());
        }
        Sha256Digest::from_bytes(bytes)
    }

    fn compress(&mut self, block: &[u8; 64]) {
        let mut schedule = [0u32; 64];
        for (index, word) in block.chunks_exact(4).enumerate() {
            let mut fixed = [0u8; 4];
            fixed.copy_from_slice(word);
            schedule[index] = u32::from_be_bytes(fixed);
        }
        for index in 16..64 {
            let s0 = schedule[index - 15].rotate_right(7)
                ^ schedule[index - 15].rotate_right(18)
                ^ (schedule[index - 15] >> 3);
            let s1 = schedule[index - 2].rotate_right(17)
                ^ schedule[index - 2].rotate_right(19)
                ^ (schedule[index - 2] >> 10);
            schedule[index] = schedule[index - 16]
                .wrapping_add(s0)
                .wrapping_add(schedule[index - 7])
                .wrapping_add(s1);
        }

        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];
        let mut f = self.state[5];
        let mut g = self.state[6];
        let mut h = self.state[7];

        for index in 0..64 {
            let sum1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let choice = (e & f) ^ ((!e) & g);
            let temporary1 = h
                .wrapping_add(sum1)
                .wrapping_add(choice)
                .wrapping_add(ROUND_CONSTANTS[index])
                .wrapping_add(schedule[index]);
            let sum0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let temporary2 = sum0.wrapping_add(majority);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temporary1);
            d = c;
            c = b;
            b = a;
            a = temporary1.wrapping_add(temporary2);
        }

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }
}

impl ContentDigest for SoftwareSha256State {
    fn update(&mut self, bytes: &[u8]) {
        self.update_bytes(bytes);
    }

    fn finish(self: Box<Self>) -> Sha256Digest {
        (*self).finalize()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ContentHasher, sha256_cancellable};
    use std::cell::Cell;

    fn assert_digest(input: &[u8], expected: &str) {
        assert_eq!(SoftwareSha256.sha256(input).to_hex(), expected);
    }

    #[test]
    fn matches_fips_and_nist_vectors() {
        assert_digest(
            b"",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        );
        assert_digest(
            b"abc",
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        );
        assert_digest(
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
        );
        assert_digest(
            &vec![b'a'; 1_000_000],
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
        );
    }

    #[test]
    fn incremental_chunking_is_identity_preserving() {
        let input: Vec<_> = (0u8..=255).cycle().take(65_537).collect();
        let expected = SoftwareSha256.sha256(&input);
        for chunk in [1, 3, 63, 64, 65, 1024, 4097] {
            let mut state = SoftwareSha256.begin_sha256();
            for bytes in input.chunks(chunk) {
                state.update(bytes);
            }
            assert_eq!(state.finish(), expected, "chunk size {chunk}");
        }
    }

    #[test]
    fn cancellable_hash_polls_between_bounded_chunks() {
        let input = vec![0u8; 2 * 1024 * 1024 + 1];
        let polls = Cell::new(0u32);
        assert!(
            sha256_cancellable(&SoftwareSha256, &input, &|| {
                let next = polls.get() + 1;
                polls.set(next);
                next == 2
            })
            .is_err()
        );
    }
}
