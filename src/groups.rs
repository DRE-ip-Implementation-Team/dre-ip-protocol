use num_bigint::BigUint;
use rand::{CryptoRng, RngCore};

/// Concrete implementation on the NIST P-256 elliptic curve.
#[cfg(feature = "p256_impl")]
mod p256_impl;
#[cfg(feature = "p256_impl")]
pub use p256;

/// An object that can be serialized to/from a binary blob.
pub trait Serializable {
    fn to_bytes(&self) -> Box<[u8]>;
    fn from_bytes(bytes: &[u8]) -> Option<Self> where Self: Sized;
}

/// A point within a DRE-ip compatible group.
pub trait DreipPoint: Serializable {
    /// Convert to an integer as per the SEC1 encoding.
    fn to_bigint(&self) -> BigUint;
    /// Create a random point deterministically from the given data via hashing.
    fn from_hash(data: &[&[u8]]) -> Self;
}

/// A scalar within a DRE-ip compatible group.
pub trait DreipScalar {
    /// Create a scalar from the modulus of the given value.
    fn new(value: u64) -> Self;
    /// Create a securely random scalar.
    fn random(rng: impl RngCore + CryptoRng) -> Self;
    /// Create a random scalar deterministically from the given data via hashing.
    fn from_hash(data: &[&[u8]]) -> Self;
    /// Convert a scalar back to an integer.
    fn to_bigint(&self) -> BigUint;
}

/// A private key generated from a DRE-ip compatible group.
pub trait DreipPrivateKey: Serializable {
    /// The signature produced by signing with this key.
    type Signature;

    /// Sign the given message with this key.
    fn sign(&self, msg: &[u8]) -> Self::Signature;
}

/// A public key generated from a DRE-ip compatible group.
pub trait DreipPublicKey: Serializable {
    /// The signature verified by this key.
    type Signature;

    /// Verify the given message and signature with this key. Returns true if valid.
    fn verify(&self, msg: &[u8], signature: &Self::Signature) -> bool;
}

/// A DRE-ip compatible group (e.g. a DSA-like multiplicative cyclic group,
/// or an ECDSA-like additive cyclic group).
/// Note that in addition to satisfying all the constraints listed here,
/// a useful implementation of this trait must also implement arithmetic
/// on references to its `Point`s and `Scalar`s (see the trait constraints
/// in `lib.rs`).
pub trait DreipGroup {
    /// The signature produced by keys from this group.
    type Signature: Serializable;
    /// A point in this group.
    type Point: DreipPoint;
    /// A scalar in this group.
    type Scalar: DreipScalar;
    /// A private key in this group.
    type PrivateKey: DreipPrivateKey<Signature = Self::Signature>;
    /// A public key in this group.
    type PublicKey: DreipPublicKey<Signature = Self::Signature>;

    /// Create two new generators deterministically from the given bytes.
    /// For optimal security, `unique_bytes` should be never be re-used in another election.
    /// One of the returned generators may be constant, but at least one of them must be
    /// deterministically generated by a one-way function from `unique_bytes`.
    fn new_generators(unique_bytes: &[&[u8]]) -> (Self::Point, Self::Point);

    /// Randomly generate a public/private keypair.
    fn new_keys(rng: impl RngCore + CryptoRng) -> (Self::PrivateKey, Self::PublicKey);
}
