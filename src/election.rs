use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::hash::Hash;
use std::time::{Duration, Instant};

use crate::ballots::{Ballot, VerificationError, VoteSecrets};
use crate::group::{DreipGroup, DreipPoint, DreipScalar};

/// An election using the given group.
#[derive(Debug, Eq, PartialEq, Clone, Deserialize, Serialize)]
#[serde(bound = "")]
pub struct Election<G: DreipGroup> {
    /// First generator.
    #[serde(with = "crate::group::serde_bytestring")]
    pub g1: G::Point,

    /// Second generator.
    #[serde(with = "crate::group::serde_bytestring")]
    pub g2: G::Point,

    /// Signing key.
    #[serde(with = "crate::group::serde_bytestring")]
    pub private_key: G::PrivateKey,

    /// Verification key.
    #[serde(with = "crate::group::serde_bytestring")]
    pub public_key: G::PublicKey,
}

impl<G: DreipGroup> Election<G> {
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
            private_key,
            public_key,
        }
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

/// Verify all of the given ballots, and the total tallies.
/// `ballots` should map ballot IDs to ballots, while `totals` should map
/// candidate ids to `CandidateTotals`.
///
/// Note that this is not sufficient for end-to-end verification; we also need
/// to verify the integrity of all audited ballots, and check the signatures of
/// all receipts. These tasks are left to the user of this library.
pub fn verify_election<G, B, C, S>(
    g1: G::Point,
    g2: G::Point,
    ballots: &HashMap<B, Ballot<C, G, S>>,
    totals: &HashMap<C, CandidateTotals<G>>,
) -> Result<(Duration, Duration, Duration), VerificationError<B, C>>
where
    G: DreipGroup,
    B: AsRef<[u8]> + Clone,
    C: AsRef<[u8]> + Eq + Hash + Clone + Ord,
    S: VoteSecrets<G>,
{
    // Verify individual ballots.
    let mut vote_dur = Duration::ZERO;
    let mut pwf_dur = Duration::ZERO;

    for (ballot_id, ballot) in ballots.iter() {
        let (vd, pd) = ballot
            .verify(g1, g2, ballot_id.clone())
            .map_err(|e| VerificationError::Ballot(e))?;
        vote_dur += vd;
        pwf_dur += pd;
    }

    // Calculate true totals.
    let start = Instant::now();
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
    if true_totals.len() != totals.len() || !true_totals.keys().all(|k| totals.contains_key(k)) {
        return Err(VerificationError::WrongCandidates);
    }
    for (candidate_id, CandidateTotals { tally, r_sum }) in totals.iter() {
        let true_totals = true_totals.get(candidate_id).expect("Already checked");
        if g1 * (*tally + *r_sum) != true_totals.0 || g2 * *r_sum != true_totals.1 {
            return Err(VerificationError::Tally {
                candidate_id: candidate_id.clone(),
            });
        }
    }
    let tally_dur = start.elapsed();

    Ok((vote_dur, pwf_dur, tally_dur))
}
