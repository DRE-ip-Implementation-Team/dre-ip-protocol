use rand::{CryptoRng, RngCore};
use std::collections::HashMap;
use std::hash::Hash;
use std::ops::{Add, Mul, Sub};

use crate::group::{DreipGroup, DreipPoint, DreipPrivateKey, DreipPublicKey, DreipScalar, Serializable};
use crate::pwf::{BallotProof, VoteProof};

/// A single vote, representing a yes/no value for a single candidate.
#[allow(non_snake_case)]
#[derive(Eq, PartialEq)]
pub struct Vote<G: DreipGroup> {
    /// The secret random value.
    pub r: G::Scalar,
    /// The secret vote value: 1 for yes or 0 for no.
    pub v: G::Scalar,
    /// The public R value (g2^r).
    pub R: G::Point,
    /// The public Z value (g1^(r+v)).
    pub Z: G::Point,
    /// The proof of well-formedness that guarantees `R` and `Z` were calculated correctly.
    pub pwf: VoteProof<G>,
}

impl<G> Vote<G>
where
    G: DreipGroup,
    G::Scalar: Eq,
    for<'a> &'a G::Point:
        Add<Output = G::Point> +
        Sub<Output = G::Point> +
        Mul<&'a G::Scalar, Output = G::Point>,
    for<'a> &'a G::Scalar:
        Add<Output = G::Scalar> +
        Sub<Output = G::Scalar> +
        Mul<Output = G::Scalar>
{
    /// Verify the PWF of this vote.
    pub fn verify(&self, election: &Election<G>, ballot_id: impl AsRef<[u8]>,
                  candidate_id: impl AsRef<[u8]>) -> bool {
        self.pwf.verify(election, &self.Z, &self.R, ballot_id, candidate_id).is_some()
    }

    /// Turn this vote into a byte sequence, suitable for signing.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend(self.r.to_bytes());
        bytes.extend(self.v.to_bytes());
        bytes.extend(self.R.to_bytes());
        bytes.extend(self.Z.to_bytes());
        bytes.extend(self.pwf.to_bytes());

        bytes
    }
}

/// A single ballot, representing a yes for exactly one candidate across a set of candidates.
pub struct Ballot<C, G: DreipGroup> {
    /// Map from candidate IDs to individual votes.
    pub votes: HashMap<C, Vote<G>>,
    /// The proof of well-formedness that guarantees exactly one of the `votes` represents yes.
    pub pwf: BallotProof<G>,
    /// The signature of the ballot, verifying authenticity and integrity.
    pub signature: G::Signature,
}

impl<C, G> Ballot<C, G>
where
    C: AsRef<[u8]>,
    G: DreipGroup,
    G::Point: Eq,
    G::Scalar: Eq,
    for<'a> &'a G::Point:
        Add<Output = G::Point> +
        Sub<Output = G::Point> +
        Mul<&'a G::Scalar, Output = G::Point>,
    for<'a> &'a G::Scalar:
        Add<Output = G::Scalar> +
        Sub<Output = G::Scalar> +
        Mul<Output = G::Scalar>
{
    /// Verify all PWFs within this ballot.
    #[allow(non_snake_case)]
    pub fn verify(&self, election: &Election<G>, ballot_id: impl AsRef<[u8]>) -> bool {
        // Verify individual vote proofs.
        let votes_valid = self.votes.iter()
            .all(|(candidate, vote)| vote.verify(election, &ballot_id, candidate));
        if !votes_valid {
            return false;
        }

        // Verify the ballot proof.
        let Z_sum: G::Point = self.votes.values()
            .map(|vote| &vote.Z)
            .fold(G::Point::identity(), |a, b| &a + b);
        let R_sum: G::Point = self.votes.values()
            .map(|vote| &vote.R)
            .fold(G::Point::identity(), |a, b| &a + b);
        let ballot_valid = self.pwf.verify(election, &Z_sum, &R_sum, &ballot_id);
        if ballot_valid.is_none() {
            return false;
        }

        // Verify signature
        let mut expected_bytes = Vec::new();
        expected_bytes.extend(election.g1.to_bytes());
        expected_bytes.extend(election.g2.to_bytes());
        expected_bytes.extend(ballot_id.as_ref());
        for (candidate, vote) in self.votes.iter() {
            expected_bytes.extend(candidate.as_ref());
            expected_bytes.extend(vote.to_bytes());
        }
        expected_bytes.extend(self.pwf.to_bytes());
        election.public_key.verify(&expected_bytes, &self.signature)
    }
}

/// An election using the given group.
#[derive(Debug)]
pub struct Election<G: DreipGroup> {
    /// First generator.
    pub g1: G::Point,
    /// Second generator.
    pub g2: G::Point,
    /// Signing key.
    pub private_key: G::PrivateKey,
    /// Verification key.
    pub public_key: G::PublicKey,
}

/// Our trait constraints look scary here, but they simply require arithmetic to
/// be defined on our group. The first set is point arithmetic, structured like
/// an additive group (a multiplicative group could easily be converted with
/// a wrapper type). The second set is scalar arithmetic.
impl<G> Election<G> where
    G: DreipGroup,
    G::Point: Eq,
    G::Scalar: Eq,
    for<'a> &'a G::Point:
        Add<Output = G::Point> +
        Sub<Output = G::Point> +
        Mul<&'a G::Scalar, Output = G::Point>,
    for<'a> &'a G::Scalar:
        Add<Output = G::Scalar> +
        Sub<Output = G::Scalar> +
        Mul<Output = G::Scalar>
{
    /// Create a new election with random generators and keys.
    pub fn new(unique_bytes: &[&[u8]], rng: impl RngCore + CryptoRng) -> Self {
        let (g1, g2) = G::new_generators(unique_bytes);
        let (private_key, public_key) = G::new_keys(rng);
        Self {
            g1,
            g2,
            private_key,
            public_key,
        }
    }

    /// Create a new ballot, representing a yes vote for the given candidate, and a no vote for all
    /// the other given candidates.
    /// This will fail if any candidate IDs are duplicates.
    pub fn create_ballot<B, C>(&self, mut rng: impl RngCore + CryptoRng, ballot_id: B,
                               yes_candidate: C, no_candidates: Vec<C>) -> Option<Ballot<C, G>>
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
        // Create PWF.
        let r_sum: G::Scalar = votes.values()
            .map(|vote| &vote.r)
            .fold(G::Scalar::zero(), |a, b| &a + b);
        let pwf = BallotProof::new(rng, self, &r_sum, &ballot_id);

        // Create signature.
        let mut bytes = Vec::new();
        bytes.extend(self.g1.to_bytes());
        bytes.extend(self.g2.to_bytes());
        bytes.extend(ballot_id.as_ref());
        for (candidate, vote) in votes.iter() {
            bytes.extend(candidate.as_ref());
            bytes.extend(vote.to_bytes());
        }
        bytes.extend(pwf.to_bytes());
        let signature = self.private_key.sign(&bytes);

        Some(Ballot {
            votes,
            pwf,
            signature,
        })
    }

    #[allow(non_snake_case)]
    pub fn create_vote(&self, rng: impl RngCore + CryptoRng, ballot_id: impl AsRef<[u8]>,
                       candidate: impl AsRef<[u8]>, yes: bool) -> Vote<G> {
        // Choose secret random r.
        let r = G::Scalar::random(rand::thread_rng());
        // Select secret vote v.
        let v = if yes {
            G::Scalar::one()
        } else {
            G::Scalar::zero()
        };
        // Calculate public random R.
        let R = &self.g2 * &r;
        // Calculate public vote Z.
        let Z = &self.g1 * &(&r + &v);
        // Create PWF.
        let pwf = VoteProof::new(rng, self, yes, &r, &Z, &R, ballot_id, candidate);

        Vote {
            r,
            v,
            R,
            Z,
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
