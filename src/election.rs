use rand::{CryptoRng, RngCore};
use std::collections::HashMap;
use std::hash::Hash;
use std::ops::{Add, Mul, Sub};

use crate::group::{DreipGroup, DreipPoint, DreipPrivateKey, DreipPublicKey, DreipScalar, Serializable};
use crate::pwf::{BallotProof, VoteProof};

/// A single vote, representing a yes/no value for a single candidate.
#[allow(non_snake_case)]
#[derive(Debug, Eq, PartialEq)]
pub struct Vote {
    /// The secret random value.
    pub r: Vec<u8>,
    /// The secret vote value: 1 for yes or 0 for no.
    pub v: Vec<u8>,
    /// The public R value (g2^r).
    pub R: Vec<u8>,
    /// The public Z value (g1^(r+v)).
    pub Z: Vec<u8>,
    /// The proof of well-formedness that guarantees `R` and `Z` were calculated correctly.
    pub pwf: VoteProof,
}

impl Vote {
    /// Verify the PWF of this vote.
    pub fn verify<G>(&self, election: &Election<G>,
                     ballot_id: impl AsRef<[u8]>, candidate_id: impl AsRef<[u8]>) -> bool
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
        self.pwf.verify(election, &self.Z, &self.R, ballot_id, candidate_id).is_some()
    }

    /// Turn this vote into a byte sequence, suitable for signing.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.r);
        bytes.extend_from_slice(&self.v);
        bytes.extend_from_slice(&self.R);
        bytes.extend_from_slice(&self.Z);
        bytes.extend_from_slice(&self.pwf.to_bytes());

        bytes
    }
}

/// A single ballot, representing a yes for exactly one candidate across a set of candidates.
/// The type parameter `K` is the candidate ID type.
#[derive(Debug)]
pub struct Ballot<K> {
    /// Map from candidate IDs to individual votes.
    pub votes: HashMap<K, Vote>,
    /// The proof of well-formedness that guarantees exactly one of the `votes` represents yes.
    pub pwf: BallotProof,
    /// The signature of the ballot, verifying authenticity and integrity.
    pub signature: Vec<u8>,
}

impl<K> Ballot<K> {
    /// Verify all PWFs within this ballot.
    #[allow(non_snake_case)]
    pub fn verify<G>(&self, election: &Election<G>, ballot_id: impl AsRef<[u8]>) -> bool
    where
        K: AsRef<[u8]>,
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
        // Verify individual vote proofs.
        let votes_valid = self.votes.iter()
            .all(|(candidate, vote)| vote.verify(election, &ballot_id, candidate));
        if !votes_valid {
            return false;
        }

        // Verify the ballot proof.
        let Z_values = self.votes.values()
            .map(|vote| G::Point::from_bytes(&vote.Z))
            .collect::<Option<Vec<_>>>();
        let Z_sum: G::Point = match Z_values {
            Some(zv) => {
                let zero = G::Point::identity();
                zv.into_iter().fold(zero, |a, b| &a + &b)
            },
            None => return false,
        };
        let R_values = self.votes.values()
            .map(|vote| G::Point::from_bytes(&vote.R))
            .collect::<Option<Vec<_>>>();
        let R_sum = match R_values {
            Some(rv) => {
                let zero = G::Point::identity();
                rv.into_iter().fold(zero, |a, b| &a + &b)
            },
            None => return false,
        };
        let ballot_valid = self.pwf.verify(election, &Z_sum, &R_sum, &ballot_id);
        if ballot_valid.is_none() {
            return false;
        }

        // Verify signature
        let mut expected_bytes = Vec::new();
        expected_bytes.extend_from_slice(&election.g1().to_bytes());
        expected_bytes.extend_from_slice(&election.g2().to_bytes());
        expected_bytes.extend(ballot_id.as_ref());
        for (candidate, vote) in self.votes.iter() {
            expected_bytes.extend(candidate.as_ref());
            expected_bytes.extend_from_slice(&vote.to_bytes());
        }
        expected_bytes.extend_from_slice(&self.pwf.to_bytes());
        let signature = G::Signature::from_bytes(&self.signature);
        if let Some(sig) = signature {
            election.public_key().verify(&expected_bytes, &sig)
        } else {
            false
        }
    }
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

    /// Create an election from its raw parts.
    pub fn from_parts(g1: G::Point, g2: G::Point, private_key: G::PrivateKey,
                      public_key: G::PublicKey) -> Self {
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
        // Create PWF.
        let zero = G::Scalar::zero();
        let r_sum: G::Scalar = votes.values()
            .map(|vote| G::Scalar::from_bytes(&vote.r).expect("Infallible"))
            .fold(zero, |a, b| &a + &b);
        let pwf = BallotProof::new(rng, self, &r_sum, &ballot_id);

        // Create signature.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.g1.to_bytes());
        bytes.extend_from_slice(&self.g2.to_bytes());
        bytes.extend(ballot_id.as_ref());
        for (candidate, vote) in votes.iter() {
            bytes.extend(candidate.as_ref());
            bytes.extend_from_slice(&vote.to_bytes());
        }
        bytes.extend_from_slice(&pwf.to_bytes());
        let signature = self.private_key.sign(&bytes);

        Some(Ballot {
            votes,
            pwf,
            signature: signature.to_bytes(),
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
            r: r.to_bytes(),
            v: v.to_bytes(),
            R: R.to_bytes(),
            Z: Z.to_bytes(),
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
