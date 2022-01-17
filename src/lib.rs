use std::collections::HashMap;
use std::hash::Hash;
use std::ops::{Add, Mul, Sub};
use num_bigint::BigUint;
use rand::{CryptoRng, RngCore};

pub mod groups;

use crate::groups::{DREipGroup, DREipPoint, DREipScalar, Serializable};

/// TODO
pub struct PWF;

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
    pub pwf: PWF,
}

/// A single ballot, representing a yes for exactly one candidate across a set of candidates.
/// The type parameter `K` is the candidate ID type.
pub struct Ballot<K> {
    /// Map from candidate IDs to individual votes.
    pub votes: HashMap<K, Vote>,
    /// The proof of well-formedness that guarantees exactly one of the `votes` represents yes.
    pub pwf: PWF,
    /// The signature of the ballot, verifying authenticity and integrity.
    pub signature: Box<[u8]>,
}

/// An election using the given group.
#[derive(Debug)]
pub struct Election<G: DREipGroup> {
    /// First generator.
    g1: G::Point,
    /// Second generator.
    g2: G::Point,
    /// Signing key.
    private_key: G::PrivateKey,
    /// Verification key.
    public_key: G::PublicKey,
}

impl<G: DREipGroup> Election<G>
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
    pub fn get_g1(&self) -> Box<[u8]> {
        self.g1.to_bytes()
    }

    /// Get the second generator.
    pub fn get_g2(&self) -> Box<[u8]> {
        self.g2.to_bytes()
    }

    /// Get the public key.
    pub fn get_public_key(&self) -> Box<[u8]> {
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
        let pwf = PWF;

        // TODO create signature.
        let signature = vec![].into_boxed_slice();

        Some(Ballot {
            votes,
            pwf,
            signature,
        })
    }

    #[allow(non_snake_case)]
    fn create_vote<K>(&self, candidate: &K, yes: bool) -> Vote {
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
        let pwf = PWF;

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
