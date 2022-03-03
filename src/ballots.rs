use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::hash::Hash;

use crate::election::CandidateTotals;
use crate::group::{DreipGroup, DreipPoint, Serializable};
use crate::pwf::{BallotProof, VoteProof};

/// An error due to a vote failing verification.
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct VoteError<B, C> {
    pub ballot_id: B,
    pub candidate_id: C,
}

/// An error due to a ballot failing verification.
#[derive(Debug, Eq, PartialEq, Clone)]
pub enum BallotError<B, C> {
    /// An individual vote failed to verify.
    Vote(VoteError<B, C>),
    /// The overall ballot proof failed to verify.
    BallotProof { ballot_id: B },
}

/// An error due to an election failing verification.
#[derive(Debug, Eq, PartialEq, Clone)]
pub enum VerificationError<B, C> {
    /// An individual ballot failed to verify.
    Ballot(BallotError<B, C>),
    /// A candidate's tally or random sum failed to verify.
    Tally { candidate_id: C },
    /// The set of candidates does not match between the ballots
    /// and the proposed tallies.
    WrongCandidates,
}

/// Vote secrets are the `r` and `v` values.
#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(bound = "")]
pub struct VoteSecrets<G: DreipGroup> {
    /// The secret random value.
    #[serde(with = "crate::group::serde_bytestring")]
    pub r: G::Scalar,

    /// The secret vote value: 1 for yes or 0 for no.
    #[serde(with = "crate::group::serde_bytestring")]
    pub v: G::Scalar,
}

impl<'a, G: DreipGroup> From<&'a VoteSecrets<G>> for Vec<u8> {
    fn from(secrets: &'a VoteSecrets<G>) -> Self {
        let mut bytes = Vec::new();
        bytes.extend(secrets.r.to_bytes());
        bytes.extend(secrets.v.to_bytes());

        bytes
    }
}

/// No secrets present.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Deserialize, Serialize)]
pub struct NoSecrets(#[serde(skip)] pub ());

impl<'a> From<&'a NoSecrets> for Vec<u8> {
    fn from(_: &'a NoSecrets) -> Self {
        Vec::new()
    }
}

/// A single vote, representing a yes/no value for a single candidate.
#[allow(non_snake_case)]
#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(bound(serialize = "S: Serialize", deserialize = "S: Deserialize<'de>"))]
pub struct Vote<G: DreipGroup, S> {
    /// Secrets.
    #[serde(flatten)]
    pub secrets: S,

    /// The public R value (g2^r).
    #[serde(with = "crate::group::serde_bytestring")]
    pub R: G::Point,

    /// The public Z value (g1^(r+v)).
    #[serde(with = "crate::group::serde_bytestring")]
    pub Z: G::Point,

    /// The proof of well-formedness that guarantees `R` and `Z` were calculated correctly.
    pub pwf: VoteProof<G>,
}

impl<G: DreipGroup, S> Vote<G, S> {
    /// Verify the PWF of this vote.
    pub fn verify<B, C>(
        &self,
        g1: G::Point,
        g2: G::Point,
        ballot_id: B,
        candidate_id: C,
    ) -> Result<(), VoteError<B, C>>
    where
        B: AsRef<[u8]>,
        C: AsRef<[u8]>,
    {
        self.pwf
            .verify(g1, g2, self.Z, self.R, &ballot_id, &candidate_id)
            .ok_or(VoteError {
                ballot_id,
                candidate_id,
            })
    }
}

impl<G: DreipGroup, S> Vote<G, S>
where
    for<'a> &'a S: Into<Vec<u8>>,
{
    /// Convert to bytes for signing.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend::<Vec<u8>>((&self.secrets).into());
        bytes.extend(self.R.to_bytes());
        bytes.extend(self.Z.to_bytes());
        bytes.extend(self.pwf.to_bytes());

        bytes
    }
}

impl<G: DreipGroup> Vote<G, VoteSecrets<G>> {
    /// Confirm this vote, discarding `r` and `v`.
    pub fn confirm(self) -> Vote<G, NoSecrets> {
        Vote {
            secrets: NoSecrets(()),
            R: self.R,
            Z: self.Z,
            pwf: self.pwf,
        }
    }
}

/// A single ballot, representing a yes for exactly one candidate across a set of candidates.
#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(bound(
    serialize = "C: Serialize, S: Serialize",
    deserialize = "C: Deserialize<'de>, S: Deserialize<'de>"
))]
pub struct Ballot<C, G, S>
where
    C: Hash + Eq,
    G: DreipGroup,
{
    /// Map from candidate IDs to individual votes.
    pub votes: HashMap<C, Vote<G, S>>,

    /// The proof of well-formedness that guarantees exactly one of the `votes` represents yes.
    pub pwf: BallotProof<G>,
}

impl<C, G, S> Ballot<C, G, S>
where
    C: AsRef<[u8]> + Clone + Hash + Eq + Ord,
    G: DreipGroup,
    for<'a> &'a S: Into<Vec<u8>>,
{
    /// Convert to bytes for signing.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        // Hashmap order is nondeterministic, ensure we iterate in a consistent order.
        let mut votes = self.votes.iter().collect::<Vec<_>>();
        votes.sort_by_key(|(c, _)| *c);
        for (candidate, vote) in votes {
            bytes.extend(candidate.as_ref());
            bytes.extend(vote.to_bytes());
        }
        bytes.extend(self.pwf.to_bytes());

        bytes
    }
}

impl<C, G, S> Ballot<C, G, S>
where
    C: Hash + Eq + Clone + AsRef<[u8]>,
    G: DreipGroup,
{
    /// Verify all PWFs within this ballot.
    #[allow(non_snake_case)]
    pub fn verify<B>(
        &self,
        g1: G::Point,
        g2: G::Point,
        ballot_id: B,
    ) -> Result<(), BallotError<B, C>>
    where
        B: AsRef<[u8]> + Clone,
    {
        // Verify individual vote proofs.
        for (candidate, vote) in self.votes.iter() {
            vote.verify(g1, g2, ballot_id.clone(), candidate.clone())
                .map_err(|e| BallotError::Vote(e))?;
        }

        // Verify the ballot proof.
        let Z_sum: G::Point = self
            .votes
            .values()
            .map(|vote| vote.Z)
            .fold(G::Point::identity(), |a, b| a + b);
        let R_sum: G::Point = self
            .votes
            .values()
            .map(|vote| vote.R)
            .fold(G::Point::identity(), |a, b| a + b);
        self.pwf
            .verify(g1, g2, Z_sum, R_sum, &ballot_id)
            .ok_or(BallotError::BallotProof { ballot_id })
    }
}

impl<C, G> Ballot<C, G, VoteSecrets<G>>
where
    C: Hash + Eq + Clone,
    G: DreipGroup,
    G::Scalar: Eq,
{
    /// Confirm this ballot, discarding all `r` and `v` values.
    /// If `totals` is provided, the candidate totals will be appropriately
    /// incremented before discarding the values. If provided, `totals` must
    /// contain an entry for every candidate or a panic will occur.
    pub fn confirm(
        self,
        totals: Option<&mut HashMap<C, &mut CandidateTotals<G>>>,
    ) -> Ballot<C, G, NoSecrets> {
        // Increment totals if provided.
        if let Some(totals) = totals {
            for (candidate, vote) in self.votes.iter() {
                let entry = totals.get_mut(candidate).unwrap();
                entry.tally = entry.tally + vote.secrets.v;
                entry.r_sum = entry.r_sum + vote.secrets.r;
            }
        }

        // Drop the secrets.
        let votes = self
            .votes
            .into_iter()
            .map(|(c, v)| (c, v.confirm()))
            .collect::<HashMap<_, _>>();

        Ballot {
            votes,
            pwf: self.pwf,
        }
    }
}