use super::*;

use p256::{AffinePoint, EncodedPoint, NistP256, ProjectivePoint, Scalar};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::ecdsa::signature::{Signature as SignatureTrait, Signer, Verifier};
use p256::elliptic_curve::{DecompressPoint, Field, Group};
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use p256::elliptic_curve::subtle::{Choice, ConstantTimeEq};
use sha2::{Digest, Sha256};

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

impl DREipPoint for ProjectivePoint {
    /// Encode as SEC1 format.
    fn to_bigint(&self) -> BigUint {
        BigUint::from_bytes_be(&self.to_bytes())
    }
}

impl DREipScalar for Scalar {
    fn new(value: u64) -> Self {
        Scalar::from(value)
    }

    fn random(rng: impl RngCore + CryptoRng) -> Self {
        <Scalar as Field>::random(rng)
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

impl DREipPrivateKey for SigningKey {
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

impl DREipPublicKey for VerifyingKey {
    type Signature = Signature;

    fn verify(&self, msg: &[u8], signature: &Self::Signature) -> bool {
        Verifier::verify(self, msg, signature).is_ok()
    }
}

impl DREipGroup for NistP256 {
    type Signature = Signature;
    type Point = ProjectivePoint;
    type Scalar = Scalar;
    type PrivateKey = SigningKey;
    type PublicKey = VerifyingKey;

    fn new_generators(unique_bytes: impl AsRef<[u8]>) -> (Self::Point, Self::Point) {
        // The first generator can be the standard one.
        let g1 = ProjectivePoint::generator();

        // The second generator must be randomly generated.
        for i in 0..=u32::MAX {
            // Generate a random x value.
            let mut hasher: Sha256 = Sha256::new();
            hasher.update(unique_bytes.as_ref());
            hasher.update(&i.to_le_bytes());
            let hash = hasher.finalize();
            // Turn this into a curve point. This might fail, or might successfully return the point at
            // infinity. Both of these are bad.
            let g2 = AffinePoint::decompress(&hash, Choice::from(0))
                .map(|ap| ProjectivePoint::from(ap))
                .unwrap_or(ProjectivePoint::identity());
            // Ensure this isn't the point at infinity.
            // Also sanity check that we haven't accidentally produced g1.
            if (!g2.is_identity() & !g1.ct_eq(&g2)).into() {
                return (g1, g2);
            }
            // Otherwise, try again with a different hash.
        }
        panic!("Tried four billion values and none worked!")
    }

    fn new_keys(rng: impl RngCore + CryptoRng) -> (Self::PrivateKey, Self::PublicKey) {
        let private_key = SigningKey::random(rng);
        let public_key = VerifyingKey::from(&private_key);
        (private_key, public_key)
    }

    fn generate(gen: &Self::Point, scalar: &Self::Scalar) -> Self::Point {
        gen * scalar
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signing() {
        let mut rng = rand::thread_rng();
        let (priv_key, pub_key) = NistP256::new_keys(&mut rng);

        // Sign and verify.
        let msg = b"This is a message.";
        let signature = DREipPrivateKey::sign(&priv_key, msg);
        assert!(DREipPublicKey::verify(&pub_key, msg, &signature));

        // Serialize-deserialize and verify.
        let signature = <Signature as Serializable>::from_bytes(&signature.to_bytes()).unwrap();
        assert!(DREipPublicKey::verify(&pub_key, msg, &signature));

        // Serialize-deserialize the keys and verify.
        let pub_key = VerifyingKey::from_bytes(&pub_key.to_bytes()).unwrap();
        assert!(DREipPublicKey::verify(&pub_key, msg, &signature));
        let priv_key = SigningKey::from_bytes(&priv_key.to_bytes()).unwrap();
        let signature = DREipPrivateKey::sign(&priv_key, msg);
        assert!(DREipPublicKey::verify(&pub_key, msg, &signature));

        // Message mismatch.
        let different_msg = b"This is a different message.";
        assert!(!DREipPublicKey::verify(&pub_key, different_msg, &signature));
        let different_sig = DREipPrivateKey::sign(&priv_key, different_msg);
        assert_ne!(signature, different_sig);
        assert!(!DREipPublicKey::verify(&pub_key, msg, &different_sig));

        // Key mismatch.
        let (new_priv, new_pub) = NistP256::new_keys(&mut rng);
        assert!(!DREipPublicKey::verify(&new_pub, msg, &signature));
        let new_sig = DREipPrivateKey::sign(&new_priv, msg);
        assert!(!DREipPublicKey::verify(&pub_key, msg, &new_sig));
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
            let (g1, g2) = NistP256::new_generators(unique_str);
            assert_ne!(g1, g2);
            assert!(!bool::from(g1.is_identity()));
            assert!(!bool::from(g2.is_identity()));
        }
    }
}
