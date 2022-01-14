use num_bigint::BigUint;
use p256::AffinePoint;
use p256::elliptic_curve::DecompressPoint;
use p256::elliptic_curve::group::prime::PrimeCurveAffine;
use p256::elliptic_curve::subtle::{Choice, ConstantTimeEq};
use serde::Serialize;
use sha2::{Digest, Sha256};

#[derive(Debug, Serialize)]
struct Election {
    g1: AffinePoint,
    g2: AffinePoint,
    s: BigUint,
    t: BigUint,
    priv_key: (),
    pub_key: (),
}

/// Create and return two generator base points suitable for a DRE-ip election.
/// For optimal security, `unique_bytes` should be never be re-used in another election.
/// This function returns an `Option`, but should *really* always succeed. The only failure mode
/// is if all four billion `u32` values are cycled through without finding a single valid curve point.
/// Most `unique_bytes` seeds succeed after single digit iterations.
fn get_generators(unique_bytes: impl AsRef<[u8]>) -> Option<(AffinePoint, AffinePoint)> {
    // The first generator can be the standard one.
    let g1 = AffinePoint::generator();

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
            .unwrap_or(AffinePoint::identity());
        // Ensure this isn't the point at infinity.
        // Also sanity check that we haven't accidentally produced g1.
        if (!g2.is_identity() & !g1.ct_eq(&g2)).into() {
            return Some((g1, g2));
        }
        // Otherwise, try again with a different hash.
    }

    return None;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generators() {
        let unique_strings = vec![
            "Hello, World!",
            "This is a string.",
            "According to all known laws of aviation, \
            there is no way that a bee should be able to fly.",
        ];
        for unique_str in unique_strings {
            let (g1, g2) = get_generators(unique_str).unwrap();
            assert_ne!(g1, g2);
            assert!(!bool::from(g1.is_identity()));
            assert!(!bool::from(g2.is_identity()));
        }
    }
}
