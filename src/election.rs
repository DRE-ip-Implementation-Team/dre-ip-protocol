use rand::{CryptoRng, RngCore};
use std::collections::HashMap;
use std::hash::Hash;
use std::ops::{Add, Mul, Sub};

use crate::group::{DreipGroup, DreipPoint, DreipPrivateKey, DreipPublicKey, DreipScalar, Serializable};
use crate::pwf::{BallotProof, VoteProof};

/// An error due to a vote failing verification.
#[derive(Debug, Eq, PartialEq)]
pub struct BadVoteProof<B, C> {
    pub ballot_id: B,
    pub candidate_id: C,
}

/// An error due to a ballot failing verification.
#[derive(Debug, Eq, PartialEq)]
pub enum BallotError<B, C> {
    /// An individual vote failed to verify.
    Vote(BadVoteProof<B, C>),
    /// The overall ballot proof failed to verify.
    BallotProof {ballot_id: B},
    /// The ballot signature failed to verify.
    Signature {ballot_id: B},
}

/// An error due to an election failing verification.
#[derive(Debug, Eq, PartialEq)]
pub enum VerificationError<B, C> {
    /// An individual ballot failed to verify.
    Ballot(BallotError<B, C>),
    /// A candidate's tally failed to verify.
    Tally {candidate_id: C},
    /// A candidate's random sum failed to verify.
    RSum {candidate_id: C},
    /// The set of candidates does not match between the ballots
    /// and the proposed tallies.
    WrongCandidates,
}

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
    pub fn verify<B, C>(&self, election: &Election<G>, ballot_id: B,
                        candidate_id: C) -> Result<(), BadVoteProof<B, C>>
    where
        B: AsRef<[u8]>,
        C: AsRef<[u8]>,
    {
        self.pwf.verify(election, &self.Z, &self.R, &ballot_id, &candidate_id)
            .ok_or(BadVoteProof {
                ballot_id,
                candidate_id,
            })
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
    C: AsRef<[u8]> + Clone,
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
    pub fn verify<B>(&self, election: &Election<G>, ballot_id: B) -> Result<(), BallotError<B, C>>
    where
        B: AsRef<[u8]> + Clone,
    {
        // Verify individual vote proofs.
        for (candidate, vote) in self.votes.iter() {
            vote.verify(election, ballot_id.clone(), candidate.clone())
                .map_err(|e| BallotError::Vote(e))?;
        }

        // Verify the ballot proof.
        let Z_sum: G::Point = self.votes.values()
            .map(|vote| &vote.Z)
            .fold(G::Point::identity(), |a, b| &a + b);
        let R_sum: G::Point = self.votes.values()
            .map(|vote| &vote.R)
            .fold(G::Point::identity(), |a, b| &a + b);
        self.pwf.verify(election, &Z_sum, &R_sum, &ballot_id)
            .ok_or(BallotError::BallotProof {ballot_id: ballot_id.clone()})?;

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
        if election.public_key.verify(&expected_bytes, &self.signature) {
            Ok(())
        } else {
            Err(BallotError::Signature {ballot_id})
        }
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
/// be defined on our group for both points and scalars. We treat points like an
/// additive group; a multiplicative group could easily be converted via a
/// wrapper type.
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

    /// Create a new vote, representing yes or no for a single candidate.
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

    /// Verify all of the given ballots, and the total tallies.
    /// `ballots` should map ballot IDs to ballots, while `totals` should map
    /// candidate ids to (`tally`, `random_sum`) pairs.
    pub fn verify<B, C>(&self, ballots: &HashMap<B, Ballot<C, G>>,
                        totals: &HashMap<C, (G::Scalar, G::Scalar)>)
                        -> Result<(), VerificationError<B, C>>
    where
        B: AsRef<[u8]> + Clone,
        C: AsRef<[u8]> + Eq + Hash + Clone,
    {
        // Verify individual ballots.
        for (ballot_id, ballot) in ballots.iter() {
            ballot.verify(self, ballot_id.clone())
                .map_err(|e| VerificationError::Ballot(e))?;
        }

        // Calculate true totals.
        let mut true_totals = HashMap::with_capacity(totals.len());
        for ballot in ballots.values() {
            for (candidate_id, vote) in ballot.votes.iter() {
                let entry = true_totals
                    .entry(candidate_id)
                    .or_insert((G::Point::identity(), G::Point::identity()));
                entry.0 = &entry.0 + &vote.Z;
                entry.1 = &entry.1 + &vote.R;
            }
        }

        // Verify we have the right candidates.
        if true_totals.len() != totals.len() || !true_totals.keys().all(|k| totals.contains_key(k)) {
            return Err(VerificationError::WrongCandidates);
        }
        for (candidate_id, (tally, r_sum)) in totals.iter() {
            let true_totals = true_totals.get(candidate_id).expect("Already checked");
            if &self.g1 * &(tally + r_sum) != true_totals.0 {
                return Err(VerificationError::Tally {candidate_id: candidate_id.clone()});
            }
            if &self.g2 * r_sum != true_totals.1 {
                return Err(VerificationError::RSum {candidate_id: candidate_id.clone()});
            }
        }

        Ok(())
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
