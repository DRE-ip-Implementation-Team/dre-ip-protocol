use num_bigint::BigUint;
use p256::AffinePoint;
use p256::ecdsa::{SigningKey, VerifyingKey};
use serde::Serialize;

#[derive(Debug, Serialize)]
struct Election {
    g1: AffinePoint,
    g2: AffinePoint,
    s: BigUint,
    t: BigUint,
    priv_key: (),
    pub_key: (),
}
