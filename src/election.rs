use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::hash::Hash;
use std::ops::Deref;

use crate::ballots::{Ballot, NoSecrets, VerificationError, Vote, VoteSecrets};
use crate::group::{DreipGroup, DreipPoint, DreipScalar};
use crate::pwf::{BallotProof, VoteProof};

/// An election using the given group.
#[derive(Debug, Eq, PartialEq, Clone, Deserialize, Serialize)]
#[serde(bound(serialize = "S: Serialize", deserialize = "for<'a> S: Deserialize<'a>"))]
pub struct Election<G: DreipGroup, S> {
    /// First generator.
    #[serde(with = "crate::group::serde_bytestring")]
    pub g1: G::Point,

    /// Second generator.
    #[serde(with = "crate::group::serde_bytestring")]
    pub g2: G::Point,

    /// Signing key.
    #[serde(flatten)]
    pub private_key: S,

    /// Verification key.
    #[serde(with = "crate::group::serde_bytestring")]
    pub public_key: G::PublicKey,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct PrivateKey<G: DreipGroup> {
    #[serde(with = "crate::group::serde_bytestring")]
    pub private_key: G::PrivateKey,
}

impl<G: DreipGroup> Deref for PrivateKey<G> {
    type Target = G::PrivateKey;

    fn deref(&self) -> &Self::Target {
        &self.private_key
    }
}

impl<G: DreipGroup> Election<G, PrivateKey<G>> {
    /// Create a new election with random generators and keys.
    pub fn new(unique_bytes: &[&[u8]], rng: impl RngCore + CryptoRng) -> Self {
        let (g1, g2) = G::new_generators(unique_bytes);
        // Sanity check. This should never fail, but we'd like a big loud warning if it does.
        assert_ne!(g1, G::Point::identity());
        assert_ne!(g2, G::Point::identity());
        let (private_key, public_key) = G::new_keys(rng);
        Self {
            g1,
            g2,
            private_key: PrivateKey { private_key },
            public_key,
        }
    }
}

impl<G: DreipGroup, PK> Election<G, PK> {
    /// Create a new ballot, representing a yes vote for the given candidate, and a no vote for all
    /// the other given candidates.
    /// This will fail if any candidate IDs are duplicates.
    pub fn create_ballot<B, C>(
        &self,
        mut rng: impl RngCore + CryptoRng,
        ballot_id: B,
        yes_candidate: C,
        no_candidates: impl IntoIterator<Item = C>,
    ) -> Option<Ballot<C, G, VoteSecrets<G>>>
    where
        B: AsRef<[u8]>,
        C: AsRef<[u8]> + Eq + Hash,
    {
        let no_candidates = no_candidates.into_iter();

        let mut votes = if let (_, Some(len)) = no_candidates.size_hint() {
            HashMap::with_capacity(len)
        } else {
            HashMap::new()
        };

        // Create yes vote.
        let yes_vote = self.create_vote(&mut rng, &ballot_id, &yes_candidate, true);
        ensure_none(votes.insert(yes_candidate, yes_vote))?;
        // Create no votes.
        for candidate in no_candidates {
            let no_vote = self.create_vote(&mut rng, &ballot_id, &candidate, false);
            ensure_none(votes.insert(candidate, no_vote))?;
        }
        // Create PWF.
        let r_sum: G::Scalar = votes
            .values()
            .map(|vote| vote.secrets.r)
            .fold(G::Scalar::zero(), |a, b| a + b);
        let pwf = BallotProof::new(rng, self.g1, self.g2, r_sum, &ballot_id);

        Some(Ballot { votes, pwf })
    }

    /// Create a new vote, representing yes or no for a single candidate.
    #[allow(non_snake_case)]
    pub fn create_vote(
        &self,
        mut rng: impl RngCore + CryptoRng,
        ballot_id: impl AsRef<[u8]>,
        candidate: impl AsRef<[u8]>,
        yes: bool,
    ) -> Vote<G, VoteSecrets<G>> {
        // Choose secret random r.
        let r = G::Scalar::random(&mut rng);
        // Select secret vote v.
        let v = if yes {
            G::Scalar::one()
        } else {
            G::Scalar::zero()
        };
        // Calculate public random R.
        let R = self.g2 * r;
        // Calculate public vote Z.
        let Z = self.g1 * (r + v);
        // Create PWF.
        let pwf = VoteProof::new(rng, self.g1, self.g2, yes, r, Z, R, ballot_id, candidate);

        Vote {
            secrets: VoteSecrets { r, v },
            R,
            Z,
            pwf,
        }
    }

    /// Verify all of the given ballots, and the total tallies.
    /// `ballots` should map ballot IDs to ballots, while `totals` should map
    /// candidate ids to `CandidateTotals`.
    pub fn verify<B, C, S>(
        &self,
        ballots: &HashMap<B, Ballot<C, G, S>>,
        totals: &HashMap<C, CandidateTotals<G>>,
    ) -> Result<(), VerificationError<B, C>>
    where
        B: AsRef<[u8]> + Clone,
        C: AsRef<[u8]> + Eq + Hash + Clone + Ord,
    {
        // Verify individual ballots.
        for (ballot_id, ballot) in ballots.iter() {
            ballot
                .verify(self.g1, self.g2, ballot_id.clone())
                .map_err(|e| VerificationError::Ballot(e))?;
        }

        // Calculate true totals.
        let mut true_totals = HashMap::with_capacity(totals.len());
        for ballot in ballots.values() {
            for (candidate_id, vote) in ballot.votes.iter() {
                let entry = true_totals
                    .entry(candidate_id)
                    .or_insert((G::Point::identity(), G::Point::identity()));
                entry.0 = entry.0 + vote.Z;
                entry.1 = entry.1 + vote.R;
            }
        }

        // Verify we have the right candidates.
        if true_totals.len() != totals.len() || !true_totals.keys().all(|k| totals.contains_key(k))
        {
            return Err(VerificationError::WrongCandidates);
        }
        for (candidate_id, CandidateTotals { tally, r_sum }) in totals.iter() {
            let true_totals = true_totals.get(candidate_id).expect("Already checked");
            if self.g1 * (*tally + *r_sum) != true_totals.0 || self.g2 * *r_sum != true_totals.1 {
                return Err(VerificationError::Tally {
                    candidate_id: candidate_id.clone(),
                });
            }
        }

        Ok(())
    }

    /// Erase the private key, for user-facing output.
    pub fn erase_secrets(self) -> Election<G, NoSecrets> {
        Election {
            g1: self.g1,
            g2: self.g2,
            private_key: NoSecrets(()),
            public_key: self.public_key,
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

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(bound = "")]
pub struct CandidateTotals<G: DreipGroup> {
    #[serde(with = "crate::group::serde_bytestring")]
    pub tally: G::Scalar,

    #[serde(with = "crate::group::serde_bytestring")]
    pub r_sum: G::Scalar,
}

impl<G: DreipGroup> Default for CandidateTotals<G> {
    fn default() -> Self {
        Self {
            tally: G::Scalar::zero(),
            r_sum: G::Scalar::zero(),
        }
    }
}

impl<G: DreipGroup> From<(G::Scalar, G::Scalar)> for CandidateTotals<G> {
    fn from((tally, r_sum): (G::Scalar, G::Scalar)) -> Self {
        Self { tally, r_sum }
    }
}

/// An election along with its results.
#[derive(Clone, Deserialize, Serialize)]
#[serde(bound(
    serialize = "B: Serialize, C: Serialize",
    deserialize = "B: Deserialize<'de>, C: Deserialize<'de>"
))]
pub struct ElectionResults<B, C, G>
where
    B: Hash + Eq,
    C: Hash + Eq,
    G: DreipGroup,
{
    /// The election metadata.
    pub election: Election<G, NoSecrets>,

    /// All audited ballots.
    pub audited: HashMap<B, Ballot<C, G, VoteSecrets<G>>>,

    /// All confirmed ballots.
    pub confirmed: HashMap<B, Ballot<C, G, NoSecrets>>,

    /// Candidate tallies and random sums.
    pub totals: HashMap<C, CandidateTotals<G>>,
}

impl<B, C, G> ElectionResults<B, C, G>
where
    B: Hash + Eq + AsRef<[u8]> + Clone,
    C: Hash + Eq + AsRef<[u8]> + Clone + Ord,
    G: DreipGroup,
{
    /// Verify the election results.
    pub fn verify(&self) -> Result<(), VerificationError<B, C>> {
        self.election
            .verify(&self.confirmed, &self.totals)
            .and_then(|()| {
                for (ballot_id, ballot) in self.audited.iter() {
                    ballot
                        .verify(self.election.g1, self.election.g2, ballot_id.clone())
                        .map_err(|e| VerificationError::Ballot(e))?;
                }
                Ok(())
            })
    }
}
