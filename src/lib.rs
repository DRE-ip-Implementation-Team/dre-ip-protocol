use std::collections::HashMap;
use std::hash::Hash;
use std::ops::{Add, Mul, Sub};
use num_bigint::BigUint;
use rand::{CryptoRng, RngCore};

pub mod groups;

use crate::groups::{DreipGroup, DreipPoint, DreipScalar};

/// Zero-Knowledge Proof of well-formedness that a vote has `v` in `{0, 1}`.
pub struct VoteProof {
    /// Challenge value one.
    pub c1: BigUint,
    /// Challenge value two.
    pub c2: BigUint,
    /// Response value one.
    pub r1: BigUint,
    /// Response value two.
    pub r2: BigUint,
}

impl VoteProof {
    /// Create a new proof.
    ///
    /// This proof consists of two parallel sub-proofs, one of which will be
    /// genuine, and the other faked. Due to the way the sub-challenges `c1`
    /// and `c2` must sum to the primary challenge `c`, it is impossible for both
    /// to be faked. Thus, if they both verify correctly, then we have proved
    /// their disjunction without revealing which is true.
    ///
    /// Our sub-proofs are for `v=0` and `v=1`, so our overall proof is `v=0 OR v=1`.
    ///
    /// The sub-proofs work by TODO
    ///
    /// The ballot and candidate ids are hashed into the challenge, tying the
    /// proof to the vote.
    ///
    /// This function does not check the validity of the generated proof, so if
    /// the supplied `v`, `r`, `Z`, and `R` values are invalid, an invalid
    /// proof will be generated.
    ///
    /// See the `Election` impl block for an explanation of these trait constraints.
    #[allow(non_snake_case)]
    pub fn new<G>(mut rng: impl RngCore + CryptoRng, election: &Election<G>,
                  v: bool, r: &G::Scalar, Z: &G::Point, R: &G::Point,
                  ballot_id: impl AsRef<[u8]>,
                  candidate_id: impl AsRef<[u8]>) -> Self
    where
        G: DreipGroup,
        for<'a> &'a G::Point:
            Add<Output = G::Point> +
            Sub<Output = G::Point> +
            Mul<&'a G::Scalar, Output = G::Point>,
        for<'a> &'a G::Scalar:
            Add<Output = G::Scalar> +
            Sub<Output = G::Scalar> +
            Mul<Output = G::Scalar>
    {
        // Get our generators.
        let g1 = election.g1();
        let g2 = election.g2();

        // Generate the input for our genuine proof.
        let random_scalar = G::Scalar::random(&mut rng);
        let genuine_a = g1 * &random_scalar;
        let genuine_b = g2 * &random_scalar;

        // Generate our response and sub-challenge for the faked proof.
        let fake_response = G::Scalar::random(&mut rng);
        let fake_challenge = G::Scalar::random(&mut rng);

        // Our fake_a varies depending on the vote.
        let fake_a = if v {
            // Fake proof for v=0, since v really equals 1.
            &(g1 * &fake_response) + &(Z * &fake_challenge)
        } else {
            // Fake proof for v=1, since v really equals 0.
            &(g1 * &fake_response) + &( &(Z - g1) * &fake_challenge)
        };
        // Our fake_b is always the same.
        let fake_b = &(g2 * &fake_response) + &(R * &fake_challenge);

        // Get our non-interactive challenge via hashing.
        let challenge = todo!();
        // Split this into sub-challenges.
        let genuine_challenge = &challenge - &fake_challenge;
        // Calculate the genuine response.
        let genuine_response = &random_scalar - &(r * &genuine_challenge);

        // Re-order the values so (c1, r1) are always the proof for v=0 and
        // (c2, r2) are always the proof for v=1, regardless of which is fake.
        let (c1, c2, r1, r2) = if v {
            (fake_challenge, genuine_challenge, fake_response, genuine_response)
        } else {
            (genuine_challenge, fake_challenge, genuine_response, fake_response)
        };

        VoteProof {
            c1: c1.to_bigint(),
            c2: c2.to_bigint(),
            r1: r1.to_bigint(),
            r2: r2.to_bigint(),
        }
    }
}

/// Proof of well-formedness that a ballot has exactly one positive vote.
pub struct BallotProof {
    pub a: BigUint,
    pub b: BigUint,
    pub t: BigUint,
}

impl BallotProof {
    pub fn new<G: DreipGroup>(election: Election<G>, r_sum: BigUint,
                              ballot_id: impl AsRef<[u8]>) -> Self {
        todo!()
    }
}

/// A single vote, representing a yes/no value for a single candidate.
#[allow(non_snake_case)]
pub struct Vote {
    /// The random value.
    pub r: BigUint,
    /// The vote value: 1 for yes or 0 for no.
    pub v: BigUint,
    /// The R value (g2^r).
    pub R: BigUint,
    /// The Z value (g1^(r+v)).
    pub Z: BigUint,
    /// The proof of well-formedness that guarantees `v` was in `{0, 1}` when calculating `Z`.
    pub pwf: VoteProof,
}

/// A single ballot, representing a yes for exactly one candidate across a set of candidates.
/// The type parameter `K` is the candidate ID type.
pub struct Ballot<K> {
    /// Map from candidate IDs to individual votes.
    pub votes: HashMap<K, Vote>,
    /// The proof of well-formedness that guarantees exactly one of the `votes` represents yes.
    pub pwf: BallotProof,
    /// The signature of the ballot, verifying authenticity and integrity.
    pub signature: Box<[u8]>,
}

/// An election using the given group.
#[derive(Debug)]
pub struct Election<G: DreipGroup> {
    /// First generator.
    g1: G::Point,
    /// Second generator.
    g2: G::Point,
    /// Signing key.
    private_key: G::PrivateKey,
    /// Verification key.
    public_key: G::PublicKey,
}

/// Our trait constraints look scary here, but they simply require arithmetic to
/// be defined on our group. The first set is point arithmetic, structured like
/// an additive group (a multiplicative group could easily be converted with
/// a wrapper type). The second set is scalar arithmetic.
impl<G> Election<G> where
    G: DreipGroup,
    for<'a> &'a G::Point:
        Add<Output = G::Point> +
        Sub<Output = G::Point> +
        Mul<&'a G::Scalar, Output = G::Point>,
    for<'a> &'a G::Scalar:
        Add<Output = G::Scalar> +
        Sub<Output = G::Scalar> +
        Mul<Output = G::Scalar>
{
    /// Create a new election.
    pub fn new(unique_bytes: impl AsRef<[u8]>, rng: impl RngCore + CryptoRng) -> Self {
        let (g1, g2) = G::new_generators(unique_bytes);
        let (private_key, public_key) = G::new_keys(rng);
        Self {
            g1,
            g2,
            private_key,
            public_key,
        }
    }

    /// Get the first generator.
    pub fn g1(&self) -> &G::Point {
        &self.g1
    }

    /// Get the second generator.
    pub fn g2(&self) -> &G::Point {
        &self.g2
    }

    /// Get the public key.
    pub fn public_key(&self) -> &G::PublicKey {
        &self.public_key
    }

    /// Create a new ballot, representing a yes vote for the given candidate, and a no vote for all
    /// the other given candidates.
    /// This will fail if any candidate IDs are duplicates.
    pub fn create_ballot<B, C>(&self, mut rng: impl RngCore + CryptoRng, ballot_id: B,
                               yes_candidate: C, no_candidates: Vec<C>) -> Option<Ballot<C>>
    where
        B: AsRef<[u8]>,
        C: AsRef<[u8]> + Eq + Hash,
    {
        let num_candidates = no_candidates.len() + 1;
        let mut votes = HashMap::with_capacity(num_candidates);

        // Create yes vote.
        let yes_vote = self.create_vote(&mut rng, &ballot_id, &yes_candidate, true);
        ensure_none(votes.insert(yes_candidate, yes_vote))?;
        // Create no votes.
        for candidate in no_candidates {
            let no_vote = self.create_vote(&mut rng, &ballot_id, &candidate, false);
            ensure_none(votes.insert(candidate, no_vote))?;
        }
        // TODO create PWF.
        let pwf = todo!();

        // TODO create signature.
        let signature = vec![].into_boxed_slice();

        Some(Ballot {
            votes,
            pwf,
            signature,
        })
    }

    #[allow(non_snake_case)]
    pub fn create_vote<B, C>(&self, rng: impl RngCore + CryptoRng,
                             ballot_id: B, candidate: C, yes: bool) -> Vote
    where
        B: AsRef<[u8]>,
        C: AsRef<[u8]>,
    {
        // Choose secret random r.
        let r = G::Scalar::random(rand::thread_rng());
        // Select secret vote v.
        let v = if yes {
            G::Scalar::new(1)
        } else {
            G::Scalar::new(0)
        };
        // Calculate public random R.
        let R = &self.g2 * &r;
        // Calculate public vote Z.
        let Z = &self.g1 * &(&r + &v);
        // Create PWF.
        let pwf = VoteProof::new(rng, self, yes, &r, &Z, &R, ballot_id, candidate);

        Vote {
            r: r.to_bigint(),
            v: v.to_bigint(),
            R: R.to_bigint(),
            Z: Z.to_bigint(),
            pwf,
        }
    }
}

/// Invert the given option, returning `Some(())` if it is `None`, and `None` if it is `Some(_)`.
fn ensure_none<T>(option: Option<T>) -> Option<()> {
    if option.is_none() {
        Some(())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // TODO
}
