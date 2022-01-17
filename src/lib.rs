use std::collections::HashMap;
use std::hash::Hash;
use std::ops::{Add, Mul, Sub};
use num_bigint::BigUint;
use rand::{CryptoRng, RngCore};

pub mod groups;

use crate::groups::{DreipGroup, DreipPoint, DreipScalar, Serializable};

/// Zero-Knowledge Proof of well-formedness that a vote has `v` in `{0, 1}`.
pub struct VoteProof {
    pub d1: BigUint,
    pub d2: BigUint,
    pub r1: BigUint,
    pub r2: BigUint,
}

impl VoteProof {
    /// Create a new ZKPWF.
    #[allow(non_snake_case)]
    pub fn new<G: DreipGroup>(election: Election<G>, v: BigUint, r: BigUint,
                              Z: BigUint, R: BigUint, ballot_id: impl AsRef<[u8]>,
                              candidate_id: impl AsRef<[u8]>) -> Self {
        todo!()
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

impl<G: DreipGroup> Election<G>
where for<'a> &'a G::Scalar:
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
    pub fn g1(&self) -> Box<[u8]> {
        self.g1.to_bytes()
    }

    /// Get the second generator.
    pub fn g2(&self) -> Box<[u8]> {
        self.g2.to_bytes()
    }

    /// Get the public key.
    pub fn public_key(&self) -> Box<[u8]> {
        self.public_key.to_bytes()
    }

    /// Create a new ballot, representing a yes vote for the given candidate, and a no vote for all
    /// the other given candidates.
    /// This will fail if any candidate IDs are duplicates.
    pub fn create_ballot<K: Eq + Hash>(&self, yes_candidate: K, no_candidates: Vec<K>) -> Option<Ballot<K>> {
        let num_candidates = no_candidates.len() + 1;
        let mut votes = HashMap::with_capacity(num_candidates);

        // Create yes vote.
        let yes_vote = self.create_vote(&yes_candidate, true);
        ensure_none(votes.insert(yes_candidate, yes_vote))?;
        // Create no votes.
        for candidate in no_candidates {
            let no_vote = self.create_vote(&candidate, false);
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
    pub fn create_vote<K>(&self, candidate: &K, yes: bool) -> Vote {
        // Choose secret random r.
        let r = G::Scalar::random(rand::thread_rng());
        // Select secret vote v.
        let v = if yes {
            G::Scalar::new(1)
        } else {
            G::Scalar::new(0)
        };
        // Calculate public random R.
        let R = G::generate(&self.g2, &r);
        // Calculate public vote Z.
        let Z = G::generate(&self.g1, &(&r + &v));

        // TODO create PWF.
        let pwf = todo!();

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
