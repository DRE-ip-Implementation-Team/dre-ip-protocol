use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::election::Election;
use crate::group::{DreipGroup, DreipScalar, Serializable};

/// Zero-Knowledge Proof of well-formedness that a vote has `v` in `{0, 1}`.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(bound = "")]
pub struct VoteProof<G: DreipGroup> {
    /// Challenge value one.
    #[serde(with = "crate::group::serde_bytestring")]
    pub c1: G::Scalar,
    /// Challenge value two.
    #[serde(with = "crate::group::serde_bytestring")]
    pub c2: G::Scalar,
    /// Response value one.
    #[serde(with = "crate::group::serde_bytestring")]
    pub r1: G::Scalar,
    /// Response value two.
    #[serde(with = "crate::group::serde_bytestring")]
    pub r2: G::Scalar,
}

impl<G: DreipGroup> VoteProof<G> {
    /// Create a new proof.
    ///
    /// This proof consists of two parallel sub-proofs, one of which will be
    /// genuine, and the other faked. Due to the way the sub-challenges `c1`
    /// and `c2` must sum to the total challenge `c`, it is impossible for both
    /// to be faked. Thus, if they both verify correctly, then we have proved
    /// their disjunction without revealing which is true.
    ///
    /// Our sub-proofs are for `v=0` and `v=1`, so our overall proof is `v=0 OR v=1`.
    ///
    /// A genuine sub-proof works as follows:
    /// 1. A random scalar `rand` is generated.
    /// 2. We calculate `a = g1 * rand` and `b = g2 * rand`.
    /// 3. We generate a challenge value `c`, and receive the sub-challenge `c' = c - fake_c`,
    ///    where `fake_c` is the pre-selected sub-challenge for the fake proof.
    /// 4. We calculate our response as `resp = rand - secret * c'`, where `secret` is `vote.r`.
    /// 5. The observer can verify that `a = g1*resp + Y*c'`, where `Y` is either `Z` or `Z - g1`
    ///    depending on whether we are trying to prove v=0 or v=1 respectively. This holds, as:
    /// ```equation
    ///           g1*resp + Y*c'
    ///         = g1*(rand - secret*c') + g1*(secret*c')
    ///         = g1*(rand - secret*c' + secret*c')
    ///         = g1*rand
    ///         = a
    /// ```
    /// 6. The observer can verify that `b = g2*resp + R*c'`. This holds, as:
    /// ```equation
    ///           g2*resp + R*c'
    ///         = g2*(rand - secret*c') + g2*(secret*c')
    ///         = g2*(rand - secret*c' + secret*c')
    ///         = g2*rand
    ///         = b
    /// ```
    ///
    /// A fake sub-proof works as follows:
    /// 1. We pre-select our sub-challenge `c'` and response `resp` by randomly generating them.
    /// 2. We calculate `a = g1*resp + Y*c'`, where `Y` is either `Z` or `Z - g1` depending on whether
    ///    we are trying to fake v=0 or v=1 respectively.
    /// 3. We calculate `b = g2*resp + R*c'`.
    /// 4. The observer can verify that `a = g1*resp + Y*c'` and `b = g2*resp + R*c'`; these trivially
    ///    hold due to the way in which we constructed them.
    ///
    /// Since the total challenge `c` is generated by a hash function and is thus out of our control,
    /// we can only pick the sub-challenge for one of the two sub-proofs, the other must necessarily
    /// use a value such that the sub-challenges sum to `c`; this is enforced by the observer
    /// additionally verifying that `c1 + c2 = c`.
    ///
    /// Therefore, only one of the two sub-proofs can be faked, and we have successfully formed our
    /// zero-knowledge proof of the disjunction.
    ///
    /// The ballot and candidate ids are part of the hash input for the challenge, tying the
    /// proof to the vote. This requires that the combination of the two is globally unique.
    ///
    /// This function does not check the validity of the generated proof, so if
    /// the supplied `v`, `r`, `Z`, and `R` values are invalid, an invalid
    /// proof will be generated.
    #[allow(non_snake_case)]
    pub fn new(mut rng: impl RngCore + CryptoRng, election: &Election<G>,
               v: bool, r: G::Scalar, Z: G::Point, R: G::Point,
               ballot_id: impl AsRef<[u8]>, candidate_id: impl AsRef<[u8]>) -> Self {
        // Get our generators.
        let g1 = election.g1;
        let g2 = election.g2;

        // Generate the input for our genuine proof.
        let random_scalar = G::Scalar::random(&mut rng);
        let genuine_a = g1 * random_scalar;
        let genuine_b = g2 * random_scalar;

        // Generate our response and sub-challenge for the faked proof.
        let fake_response = G::Scalar::random(&mut rng);
        let fake_challenge = G::Scalar::random(&mut rng);

        // Our fake_a varies depending on the vote.
        let fake_a = if v {
            // Fake proof for v=0, since v really equals 1.
            g1 * fake_response + Z * fake_challenge
        } else {
            // Fake proof for v=1, since v really equals 0.
            g1 * fake_response + (Z - g1) * fake_challenge
        };
        // Our fake_b is always the same.
        let fake_b = g2 * fake_response + R * fake_challenge;

        // Ensure our `a` and `b` values are always in the right order (proof for v=0 first).
        let (a1, b1, a2, b2) = if v {
            (fake_a, fake_b, genuine_a, genuine_b)
        } else {
            (genuine_a, genuine_b, fake_a, fake_b)
        };

        // Get our non-interactive challenge via hashing.
        let challenge = G::Scalar::from_hash(&[
            &g1.to_bytes(), &g2.to_bytes(), &Z.to_bytes(), &R.to_bytes(),
            &a1.to_bytes(), &b1.to_bytes(), &a2.to_bytes(), &b2.to_bytes(),
            ballot_id.as_ref(), candidate_id.as_ref(),
        ]);
        // Split this into sub-challenges.
        let genuine_challenge = challenge - fake_challenge;
        // Calculate the genuine response.
        let genuine_response = random_scalar - r * genuine_challenge;

        // Re-order the values so (c1, r1) are always the proof for v=0 and
        // (c2, r2) are always the proof for v=1, regardless of which is fake.
        let (c1, c2, r1, r2) = if v {
            (fake_challenge, genuine_challenge, fake_response, genuine_response)
        } else {
            (genuine_challenge, fake_challenge, genuine_response, fake_response)
        };

        VoteProof {
            c1,
            c2,
            r1,
            r2,
        }
    }

    /// Verify the given proof, returning `Some(())` if verification succeeds and `None` otherwise.
    #[allow(non_snake_case)]
    pub fn verify(&self, election: &Election<G>, Z: G::Point, R: G::Point,
                  ballot_id: impl AsRef<[u8]>, candidate_id: impl AsRef<[u8]>) -> Option<()> {
        // Get our values.
        let g1 = election.g1;
        let g2 = election.g2;
        let c1 = self.c1;
        let c2 = self.c2;
        let r1 = self.r1;
        let r2 = self.r2;

        // Reconstruct the `a` and `b` values.
        let a1 = g1 * r1 + Z * c1;
        let b1 = g2 * r1 + R * c1;
        let a2 = g1 * r2 + (Z - g1) * c2;
        let b2 = g2 * r2 + R * c2;

        // Reconstruct the challenge value.
        let challenge = G::Scalar::from_hash(&[
            &g1.to_bytes(), &g2.to_bytes(), &Z.to_bytes(), &R.to_bytes(),
            &a1.to_bytes(), &b1.to_bytes(), &a2.to_bytes(), &b2.to_bytes(),
            ballot_id.as_ref(), candidate_id.as_ref(),
        ]);

        // Ensure that the challenge value matches.
        if c1 + c2 == challenge {
            Some(())
        } else {
            None
        }
    }

    /// Turn this proof into a byte sequence, suitable for signing.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend(self.c1.to_bytes());
        bytes.extend(self.c2.to_bytes());
        bytes.extend(self.r1.to_bytes());
        bytes.extend(self.r2.to_bytes());

        bytes
    }
}

/// Zero-Knowledge Proof of well-formedness that a ballot has exactly one positive vote.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(bound = "")]
pub struct BallotProof<G: DreipGroup> {
    /// Proof value a.
    #[serde(with = "crate::group::serde_bytestring")]
    pub a: G::Point,
    /// Proof value b.
    #[serde(with = "crate::group::serde_bytestring")]
    pub b: G::Point,
    /// Response value.
    #[serde(with = "crate::group::serde_bytestring")]
    pub r: G::Scalar,
}

impl<G: DreipGroup> BallotProof<G> {
    /// Create a new proof.
    ///
    /// This proof works on a similar principle to the genuine sub-proof within `VoteProof`.
    /// It works as follows:
    /// 1. We generate a random scalar `rand`.
    /// 2. We calculate `a = g1 * rand` and `b = g2 * rand`.
    /// 3. We generate a challenge value `c` which we cannot control due to the use of a hash function.
    /// 4. We calculate our response as `resp = rand + c * r_sum`, where `r_sum` is the sum of secret
    ///    `r` values across all votes in this ballot.
    /// 5. The observer can verify that `g1*resp = a + X*c`, where `X = sum(vote.Z) - g1` across
    ///    all votes in this ballot; this holds, as:
    /// ```equation
    ///           sum(vote.Z) = g1 * sum(vote.r) + g1
    ///        so X = g1 * r_sum
    ///        so a + X*c
    ///         = g1*rand + g1*(r_sum*c)
    ///         = g1 * (rand + c * r_sum)
    ///         = g1 * resp
    /// ```
    ///    If the number of yes votes is anything other than 1, then `sum(vote.Z)` will be
    ///    different and the proof would fail.
    /// 6. The observer can verify that `g2*resp = b + Y*c`, where `Y = sum(vote.R)` across all
    ///    votes in this ballot; this holds, as:
    /// ```equation
    ///           sum(vote.R) = g2 * sum(vote.r)
    ///        so Y = g2 * r_sum
    ///        so b + Y*c
    ///         = g2*rand + g2*(r_sum*c)
    ///         = g2 * (rand + c * r_sum)
    ///         = g2 * resp
    /// ```
    ///
    /// The ballot id is part of the hash input for the challenge, tying the proof to the ballot.
    /// This requires that the ballot id is unique.
    pub fn new(mut rng: impl RngCore + CryptoRng, election: &Election<G>,
               r_sum: G::Scalar, ballot_id: impl AsRef<[u8]>) -> Self {
        // Get our generators.
        let g1 = election.g1;
        let g2 = election.g2;

        // Generate the input for the challenge.
        let random_scalar = G::Scalar::random(&mut rng);
        let a = g1 * random_scalar;
        let b = g2 * random_scalar;

        // Get our non-interactive challenge via hashing.
        let challenge = G::Scalar::from_hash(&[
            &g1.to_bytes(), &g2.to_bytes(), &a.to_bytes(), &b.to_bytes(), ballot_id.as_ref(),
        ]);

        // Calculate the response.
        let r = random_scalar + challenge * r_sum;

        BallotProof {
            a,
            b,
            r,
        }
    }

    /// Verify the given proof, returning `Some(())` if verification succeeds and `None` otherwise.
    #[allow(non_snake_case)]
    pub fn verify(&self, election: &Election<G>, Z_sum: G::Point, R_sum: G::Point,
                  ballot_id: impl AsRef<[u8]>) -> Option<()> {
        // Get our values.
        let g1 = election.g1;
        let g2 = election.g2;
        let a = self.a;
        let b = self.b;
        let r = self.r;

        // Reconstruct the challenge value.
        let challenge = G::Scalar::from_hash(&[
            &g1.to_bytes(), &g2.to_bytes(), &a.to_bytes(), &b.to_bytes(), ballot_id.as_ref(),
        ]);

        // Verify the first equation.
        let X = Z_sum - g1;
        if g1 * r != a + X * challenge {
            return None;
        }

        // Verify the second equation.
        if g2 * r != b + R_sum * challenge {
            return None;
        }

        Some(())
    }

    /// Turn this proof into a byte sequence, suitable for signing.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend(self.a.to_bytes());
        bytes.extend(self.b.to_bytes());
        bytes.extend(self.r.to_bytes());

        bytes
    }
}
