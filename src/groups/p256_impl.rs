use super::*;

use p256::{EncodedPoint, NistP256, ProjectivePoint, Scalar};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::ecdsa::signature::{Signature as SignatureTrait, Signer, Verifier};
use p256::elliptic_curve::Field;
use p256::elliptic_curve::hash2curve::GroupDigest;
use p256::elliptic_curve::hash2field::ExpandMsgXmd;
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use sha2::Sha256;

/// A tag to ensure random oracle uniqueness as per the hash_to_curve spec.
const DOMAIN_SEPARATION_TAG: &[u8] = b"CURVE_XMD:SHA-256:DREIP";

impl Serializable for Signature {
    fn to_bytes(&self) -> Box<[u8]> {
        self.as_bytes().to_vec().into_boxed_slice()
    }

    fn from_bytes(bytes: &[u8]) -> Option<Self> where Self: Sized {
        <Signature as SignatureTrait>::from_bytes(bytes).ok()
    }
}

impl Serializable for ProjectivePoint {
    /// Encode as SEC1 format.
    fn to_bytes(&self) -> Box<[u8]> {
        self.to_encoded_point(true).to_bytes()
    }

    /// Decode from SEC1 format.
    fn from_bytes(bytes: &[u8]) -> Option<Self> where Self: Sized {
        let ep = EncodedPoint::from_bytes(bytes).ok()?;
        let pp = ProjectivePoint::from_encoded_point(&ep);
        if pp.is_some().into() {
            Some(pp.unwrap())
        } else {
            None
        }
    }
}

impl DreipPoint for ProjectivePoint {
    /// Encode as SEC1 format.
    fn to_bigint(&self) -> BigUint {
        BigUint::from_bytes_be(&self.to_bytes())
    }

    /// Create a point using SHA256, according to the hash_to_curve spec.
    fn from_hash(data: &[&[u8]]) -> Self {
        NistP256::hash_from_bytes::<ExpandMsgXmd<Sha256>>(data, DOMAIN_SEPARATION_TAG)
            .expect("Infallible")
    }
}

impl DreipScalar for Scalar {
    fn new(value: u64) -> Self {
        Scalar::from(value)
    }

    fn random(rng: impl RngCore + CryptoRng) -> Self {
        <Scalar as Field>::random(rng)
    }

    fn from_hash(data: &[&[u8]]) -> Self {
        NistP256::hash_to_scalar::<ExpandMsgXmd<Sha256>>(data, DOMAIN_SEPARATION_TAG)
            .expect("Infallible")
    }

    fn to_bigint(&self) -> BigUint {
        BigUint::from_bytes_be(self.to_bytes().as_ref())
    }
}

impl Serializable for SigningKey {
    fn to_bytes(&self) -> Box<[u8]> {
        SigningKey::to_bytes(self).to_vec().into_boxed_slice()
    }

    fn from_bytes(bytes: &[u8]) -> Option<Self> where Self: Sized {
        SigningKey::from_bytes(bytes).ok()
    }
}

impl DreipPrivateKey for SigningKey {
    type Signature = Signature;

    fn sign(&self, msg: &[u8]) -> Self::Signature {
        Signer::sign(self, msg)
    }
}

impl Serializable for VerifyingKey {
    /// Encode as SEC1 format.
    fn to_bytes(&self) -> Box<[u8]> {
        self.to_encoded_point(true).to_bytes()
    }

    /// Decode from SEC1 format.
    fn from_bytes(bytes: &[u8]) -> Option<Self> where Self: Sized {
        EncodedPoint::from_bytes(bytes)
            .ok()
            .and_then(|ep| VerifyingKey::from_encoded_point(&ep).ok())
    }
}

impl DreipPublicKey for VerifyingKey {
    type Signature = Signature;

    fn verify(&self, msg: &[u8], signature: &Self::Signature) -> bool {
        Verifier::verify(self, msg, signature).is_ok()
    }
}

impl DreipGroup for NistP256 {
    type Signature = Signature;
    type Point = ProjectivePoint;
    type Scalar = Scalar;
    type PrivateKey = SigningKey;
    type PublicKey = VerifyingKey;

    fn new_generators(unique_bytes: &[&[u8]]) -> (Self::Point, Self::Point) {
        (ProjectivePoint::GENERATOR, ProjectivePoint::from_hash(unique_bytes))
    }

    fn new_keys(rng: impl RngCore + CryptoRng) -> (Self::PrivateKey, Self::PublicKey) {
        let private_key = SigningKey::random(rng);
        let public_key = VerifyingKey::from(&private_key);
        (private_key, public_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use p256::elliptic_curve::Group;

    #[test]
    fn test_signing() {
        let mut rng = rand::thread_rng();
        let (priv_key, pub_key) = NistP256::new_keys(&mut rng);

        // Sign and verify.
        let msg = b"This is a message.";
        let signature = DreipPrivateKey::sign(&priv_key, msg);
        assert!(DreipPublicKey::verify(&pub_key, msg, &signature));

        // Serialize-deserialize and verify.
        let signature = <Signature as Serializable>::from_bytes(&signature.to_bytes()).unwrap();
        assert!(DreipPublicKey::verify(&pub_key, msg, &signature));

        // Serialize-deserialize the keys and verify.
        let pub_key = VerifyingKey::from_bytes(&pub_key.to_bytes()).unwrap();
        assert!(DreipPublicKey::verify(&pub_key, msg, &signature));
        let priv_key = SigningKey::from_bytes(&priv_key.to_bytes()).unwrap();
        let signature = DreipPrivateKey::sign(&priv_key, msg);
        assert!(DreipPublicKey::verify(&pub_key, msg, &signature));

        // Message mismatch.
        let different_msg = b"This is a different message.";
        assert!(!DreipPublicKey::verify(&pub_key, different_msg, &signature));
        let different_sig = DreipPrivateKey::sign(&priv_key, different_msg);
        assert_ne!(signature, different_sig);
        assert!(!DreipPublicKey::verify(&pub_key, msg, &different_sig));

        // Key mismatch.
        let (new_priv, new_pub) = NistP256::new_keys(&mut rng);
        assert!(!DreipPublicKey::verify(&new_pub, msg, &signature));
        let new_sig = DreipPrivateKey::sign(&new_priv, msg);
        assert!(!DreipPublicKey::verify(&pub_key, msg, &new_sig));
    }

    #[test]
    fn test_point_serialization() {
        let x = ProjectivePoint::random(rand::thread_rng());
        let serialized = <ProjectivePoint as Serializable>::to_bytes(&x);
        let y = <ProjectivePoint as Serializable>::from_bytes(&serialized).unwrap();
        assert_eq!(x, y);
    }

    #[test]
    fn test_point_to_bigint() {
        let mut encoded = vec![0; 33];  // SEC1 encoding.
        encoded[0] = 02;
        encoded[32] = 255;
        let point_x = <ProjectivePoint as Serializable>::from_bytes(&encoded).unwrap();
        let x = BigUint::from_bytes_be(&encoded);
        let y = point_x.to_bigint();
        assert_eq!(x, y);
    }

    #[test]
    fn test_scalar_serialization() {
        let x = Scalar::new(42);
        let y = x.to_bigint();
        assert_eq!(y, BigUint::from(42_u32));
    }

    #[test]
    fn test_generators() {
        let unique_strings = vec![
            "Hello, World!",
            "This is a string.",
            "According to all known laws of aviation, \
            there is no way that a bee should be able to fly.",
        ];
        for unique_str in unique_strings {
            let (g1, g2) = NistP256::new_generators(&[unique_str.as_bytes()]);
            assert_ne!(g1, g2);
            assert!(!bool::from(g1.is_identity()));
            assert!(!bool::from(g2.is_identity()));
        }
    }
}
