//! SHA-256 and SHA-384 implementations of [`rustls::crypto::hash::Hash`].
//!
//! Backed by CommonCrypto's `CC_SHA256_*` / `CC_SHA384_*` functions. The
//! `Context` state is the C-side `CC_SHA256_CTX` / `CC_SHA512_CTX` struct
//! (plain POD), which lets us implement `fork` (snapshot) by trivial memcpy.

use core::ffi::c_void;
use core::mem::MaybeUninit;

use rustls::crypto::hash::{Context, Hash, HashAlgorithm, Output};

use crate::ffi::commoncrypto as cc;

// =========================================================================
// SHA-256
// =========================================================================

#[derive(Debug)]
pub struct Sha256;

pub static SHA256: Sha256 = Sha256;

impl Hash for Sha256 {
    fn start(&self) -> Box<dyn Context> {
        let mut ctx = MaybeUninit::<cc::CC_SHA256_CTX>::uninit();
        // SAFETY: `CC_SHA256_Init` initialises every field of the context.
        unsafe {
            assert_eq!(cc::CC_SHA256_Init(ctx.as_mut_ptr()), 1);
            Box::new(Sha256Context {
                ctx: ctx.assume_init(),
            })
        }
    }

    fn hash(&self, data: &[u8]) -> Output {
        let mut out = [0u8; cc::CC_SHA256_DIGEST_LENGTH];
        // SAFETY: `data.len()` ≤ `u32::MAX` is guaranteed in practice (TLS
        // limits handshake messages to 2^24 - 1). For pathological larger
        // inputs we'd need to chunk via `Update`. Asserted defensively.
        debug_assert!(data.len() <= u32::MAX as usize);
        unsafe {
            cc::CC_SHA256(
                data.as_ptr() as *const c_void,
                data.len() as u32,
                out.as_mut_ptr(),
            );
        }
        Output::new(&out)
    }

    fn algorithm(&self) -> HashAlgorithm {
        HashAlgorithm::SHA256
    }

    fn output_len(&self) -> usize {
        cc::CC_SHA256_DIGEST_LENGTH
    }

    fn fips(&self) -> bool {
        true
    }
}

#[derive(Clone)]
struct Sha256Context {
    ctx: cc::CC_SHA256_CTX,
}

impl Context for Sha256Context {
    fn fork_finish(&self) -> Output {
        let mut clone = self.clone();
        let mut out = [0u8; cc::CC_SHA256_DIGEST_LENGTH];
        // SAFETY: `clone.ctx` is fully initialised; `out` is correctly sized.
        unsafe {
            cc::CC_SHA256_Final(out.as_mut_ptr(), &mut clone.ctx);
        }
        Output::new(&out)
    }

    fn fork(&self) -> Box<dyn Context> {
        Box::new(self.clone())
    }

    fn finish(mut self: Box<Self>) -> Output {
        let mut out = [0u8; cc::CC_SHA256_DIGEST_LENGTH];
        // SAFETY: same as `fork_finish` but consuming.
        unsafe {
            cc::CC_SHA256_Final(out.as_mut_ptr(), &mut self.ctx);
        }
        Output::new(&out)
    }

    fn update(&mut self, data: &[u8]) {
        debug_assert!(data.len() <= u32::MAX as usize);
        // SAFETY: `self.ctx` is initialised in `start`; `data` is a valid slice.
        unsafe {
            cc::CC_SHA256_Update(
                &mut self.ctx,
                data.as_ptr() as *const c_void,
                data.len() as u32,
            );
        }
    }
}

// =========================================================================
// SHA-384
// =========================================================================

#[derive(Debug)]
pub struct Sha384;

pub static SHA384: Sha384 = Sha384;

impl Hash for Sha384 {
    fn start(&self) -> Box<dyn Context> {
        let mut ctx = MaybeUninit::<cc::CC_SHA512_CTX>::uninit();
        // SAFETY: `CC_SHA384_Init` initialises every field of the context.
        unsafe {
            assert_eq!(cc::CC_SHA384_Init(ctx.as_mut_ptr()), 1);
            Box::new(Sha384Context {
                ctx: ctx.assume_init(),
            })
        }
    }

    fn hash(&self, data: &[u8]) -> Output {
        let mut out = [0u8; cc::CC_SHA384_DIGEST_LENGTH];
        debug_assert!(data.len() <= u32::MAX as usize);
        unsafe {
            cc::CC_SHA384(
                data.as_ptr() as *const c_void,
                data.len() as u32,
                out.as_mut_ptr(),
            );
        }
        Output::new(&out)
    }

    fn algorithm(&self) -> HashAlgorithm {
        HashAlgorithm::SHA384
    }

    fn output_len(&self) -> usize {
        cc::CC_SHA384_DIGEST_LENGTH
    }

    fn fips(&self) -> bool {
        true
    }
}

#[derive(Clone)]
struct Sha384Context {
    ctx: cc::CC_SHA512_CTX,
}

impl Context for Sha384Context {
    fn fork_finish(&self) -> Output {
        let mut clone = self.clone();
        let mut out = [0u8; cc::CC_SHA384_DIGEST_LENGTH];
        unsafe {
            cc::CC_SHA384_Final(out.as_mut_ptr(), &mut clone.ctx);
        }
        Output::new(&out)
    }

    fn fork(&self) -> Box<dyn Context> {
        Box::new(self.clone())
    }

    fn finish(mut self: Box<Self>) -> Output {
        let mut out = [0u8; cc::CC_SHA384_DIGEST_LENGTH];
        unsafe {
            cc::CC_SHA384_Final(out.as_mut_ptr(), &mut self.ctx);
        }
        Output::new(&out)
    }

    fn update(&mut self, data: &[u8]) {
        debug_assert!(data.len() <= u32::MAX as usize);
        unsafe {
            cc::CC_SHA384_Update(
                &mut self.ctx,
                data.as_ptr() as *const c_void,
                data.len() as u32,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// NIST CAVS empty input — SHA-256 known answer.
    #[test]
    fn sha256_empty_oneshot() {
        let h = SHA256.hash(&[]);
        let expected =
            hex::decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
                .unwrap();
        assert_eq!(h.as_ref(), expected.as_slice());
    }

    /// NIST CAVS "abc" — SHA-256 known answer.
    #[test]
    fn sha256_abc_oneshot() {
        let h = SHA256.hash(b"abc");
        let expected =
            hex::decode("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
                .unwrap();
        assert_eq!(h.as_ref(), expected.as_slice());
    }

    /// Same KAT via Update/Final path — confirms streaming agrees with oneshot.
    #[test]
    fn sha256_abc_streaming() {
        let mut ctx = SHA256.start();
        ctx.update(b"a");
        ctx.update(b"b");
        ctx.update(b"c");
        let h = ctx.finish();
        let expected =
            hex::decode("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
                .unwrap();
        assert_eq!(h.as_ref(), expected.as_slice());
    }

    /// Fork: take a snapshot mid-stream, advance original, verify snapshot
    /// finishes at the earlier state.
    #[test]
    fn sha256_fork_snapshot() {
        let mut ctx = SHA256.start();
        ctx.update(b"ab");
        let forked_digest = ctx.fork_finish();
        ctx.update(b"c");
        let full_digest = ctx.finish();

        let ab = hex::decode("fb8e20fc2e4c3f248c60c39bd652f3c1347298bb977b8b4d5903b85055620603")
            .unwrap();
        let abc = hex::decode("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
            .unwrap();
        assert_eq!(forked_digest.as_ref(), ab.as_slice());
        assert_eq!(full_digest.as_ref(), abc.as_slice());
    }

    /// NIST CAVS empty input — SHA-384 known answer.
    #[test]
    fn sha384_empty_oneshot() {
        let h = SHA384.hash(&[]);
        let expected = hex::decode(
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
        )
        .unwrap();
        assert_eq!(h.as_ref(), expected.as_slice());
    }

    /// NIST CAVS "abc" — SHA-384 known answer.
    #[test]
    fn sha384_abc_oneshot() {
        let h = SHA384.hash(b"abc");
        let expected = hex::decode(
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
        )
        .unwrap();
        assert_eq!(h.as_ref(), expected.as_slice());
    }

    /// `output_len()` and `algorithm()` are part of rustls's `Hash` trait
    /// contract. Validate them by linking to actual digest length — catches
    /// drift between accessor and implementation.
    #[test]
    fn sha256_contract_accessors_match_actual_digest() {
        let digest = SHA256.hash(b"abc");
        assert_eq!(digest.as_ref().len(), SHA256.output_len());
        assert_eq!(SHA256.output_len(), 32);
        assert_eq!(SHA256.algorithm(), HashAlgorithm::SHA256);
    }

    #[test]
    fn sha384_contract_accessors_match_actual_digest() {
        let digest = SHA384.hash(b"abc");
        assert_eq!(digest.as_ref().len(), SHA384.output_len());
        assert_eq!(SHA384.output_len(), 48);
        assert_eq!(SHA384.algorithm(), HashAlgorithm::SHA384);
    }

    /// Streaming with arbitrary chunking across SHA block boundary (>64 bytes
    /// for SHA-256, >128 for SHA-384) must equal one-shot. Catches bugs in
    /// chunk handling (off-by-one, alignment, padding boundary).
    #[test]
    fn sha256_arbitrary_chunking_equals_oneshot() {
        let data: Vec<u8> = (0..=255u8).cycle().take(200).collect(); // > 3 blocks
        let oneshot = SHA256.hash(&data);

        let mut ctx = SHA256.start();
        for chunk in data.chunks(33) {
            // 33 is intentionally non-aligned to 64-byte block size
            ctx.update(chunk);
        }
        let streamed = ctx.finish();
        assert_eq!(oneshot.as_ref(), streamed.as_ref());
    }

    #[test]
    fn sha384_arbitrary_chunking_equals_oneshot() {
        let data: Vec<u8> = (0..=255u8).cycle().take(400).collect(); // > 3 SHA-384 blocks
        let oneshot = SHA384.hash(&data);

        let mut ctx = SHA384.start();
        for chunk in data.chunks(57) {
            ctx.update(chunk);
        }
        let streamed = ctx.finish();
        assert_eq!(oneshot.as_ref(), streamed.as_ref());
    }

    /// `Context::fork` then advancing both copies independently must yield
    /// digests matching their respective separately-built digests. Catches
    /// shared-mutable-state bugs in fork.
    #[test]
    fn sha256_fork_then_diverge_remains_correct() {
        let mut a = SHA256.start();
        a.update(b"prefix");

        let mut b = a.fork();
        a.update(b"-branch-a");
        b.update(b"-branch-b");

        let digest_a = a.finish();
        let digest_b = b.finish();

        let expected_a = SHA256.hash(b"prefix-branch-a");
        let expected_b = SHA256.hash(b"prefix-branch-b");
        assert_eq!(digest_a.as_ref(), expected_a.as_ref());
        assert_eq!(digest_b.as_ref(), expected_b.as_ref());
        assert_ne!(digest_a.as_ref(), digest_b.as_ref());
    }

    /// SHA-384 streaming agrees with oneshot.
    #[test]
    fn sha384_abc_streaming() {
        let mut ctx = SHA384.start();
        ctx.update(b"a");
        ctx.update(b"b");
        ctx.update(b"c");
        let h = ctx.finish();
        let expected = hex::decode(
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
        )
        .unwrap();
        assert_eq!(h.as_ref(), expected.as_slice());
    }
}
