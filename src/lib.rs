pub mod ballots;
pub mod election;
pub mod group;
pub mod pwf;

pub use crate::ballots::{
    Ballot, BallotError, NoSecrets, VerificationError, Vote, VoteError, VoteSecrets,
};
pub use crate::election::{CandidateTotals, Election, ElectionResults};
pub use crate::group::{
    DreipGroup, DreipPoint, DreipPrivateKey, DreipPublicKey, DreipScalar, Serializable,
};
pub use crate::pwf::{BallotProof, VoteProof};

#[cfg(all(test, feature = "p256_impl"))]
mod tests {
    use super::*;

    use p256::{NistP256, Scalar};
    use std::collections::HashMap;

    use crate::group::{DreipPoint, DreipScalar};

    #[test]
    fn test_vote() {
        let mut rng = rand::thread_rng();
        let election = Election::<NistP256>::new(&[b"Test Election"], &mut rng);

        let vote1 = election.create_vote(&mut rng, "1", "Alice", true);
        assert!(vote1.verify(election.g1, election.g2, "1", "Alice").is_ok());

        let vote2 = election.create_vote(&mut rng, "1", "Bob", false);
        assert!(vote2.verify(election.g1, election.g2, "1", "Bob").is_ok());

        assert_ne!(vote1.pwf, vote2.pwf);
        assert!(vote2
            .pwf
            .verify(election.g1, election.g2, vote1.Z, vote1.R, "1", "Bob")
            .is_none());
        assert!(vote2
            .pwf
            .verify(election.g1, election.g2, vote2.Z, vote2.R, "2", "Bob")
            .is_none());
        assert!(vote2
            .pwf
            .verify(election.g1, election.g2, vote2.Z, vote2.R, "1", "Alice")
            .is_none());
    }

    #[test]
    fn test_ballot() {
        let mut rng = rand::thread_rng();
        let election = Election::<NistP256>::new(&[b"Woah some random bytes"], &mut rng);

        let mut ballot = election
            .create_ballot(&mut rng, "1", "Alice", vec!["Bob", "Eve"])
            .unwrap();
        assert!(ballot.verify(election.g1, election.g2, "1").is_ok());
        match ballot.verify(election.g1, election.g2, "2") {
            Err(BallotError::Vote(_)) => {}
            _ => panic!("Assertion failed!"),
        }

        // Modify pwf and check it fails.
        ballot.pwf.r = DreipScalar::random(&mut rng);
        assert_eq!(
            ballot.verify(election.g1, election.g2, "1"),
            Err(BallotError::BallotProof { ballot_id: "1" })
        );
    }

    #[test]
    fn test_election() {
        let mut rng = rand::thread_rng();
        let election = Election::<NistP256>::new(&[b"foobaraboof"], &mut rng);
        let mut ballots = HashMap::new();

        ballots.insert(
            "1",
            election
                .create_ballot(&mut rng, "1", "Alice", vec!["Bob", "Eve"])
                .unwrap(),
        );
        ballots.insert(
            "2",
            election
                .create_ballot(&mut rng, "2", "Bob", vec!["Alice", "Eve"])
                .unwrap(),
        );
        ballots.insert(
            "3",
            election
                .create_ballot(&mut rng, "3", "Alice", vec!["Bob", "Eve"])
                .unwrap(),
        );

        let alice_r_sum = ballots
            .values()
            .map(|b| b.votes.iter().find(|(c, _)| **c == "Alice").unwrap())
            .fold(Scalar::zero(), |a, (_, b)| &a + &b.secrets.r);
        let bob_r_sum = ballots
            .values()
            .map(|b| b.votes.iter().find(|(c, _)| **c == "Bob").unwrap())
            .fold(Scalar::zero(), |a, (_, b)| &a + &b.secrets.r);
        let eve_r_sum = ballots
            .values()
            .map(|b| b.votes.iter().find(|(c, _)| **c == "Eve").unwrap())
            .fold(Scalar::zero(), |a, (_, b)| &a + &b.secrets.r);

        let mut totals = HashMap::new();
        totals.insert("Alice", (Scalar::from(2), alice_r_sum).into());
        totals.insert("Bob", (Scalar::from(1), bob_r_sum).into());
        totals.insert("Eve", (Scalar::from(0), eve_r_sum).into());

        assert!(election.verify(&ballots, &totals).is_ok());

        // Now change the tally and check it fails.
        totals.get_mut("Eve").unwrap().tally = Scalar::from(5);
        assert_eq!(
            election.verify(&ballots, &totals),
            Err(VerificationError::Tally {
                candidate_id: "Eve"
            })
        );

        // Change the random sum and check it fails.
        totals.get_mut("Eve").unwrap().tally = Scalar::from(0);
        totals.get_mut("Alice").unwrap().r_sum = Scalar::random(&mut rng);
        assert_eq!(
            election.verify(&ballots, &totals),
            Err(VerificationError::Tally {
                candidate_id: "Alice"
            })
        );

        // Change the candidates and check it fails.
        totals.get_mut("Alice").unwrap().r_sum = alice_r_sum;
        totals.remove("Bob").unwrap();
        assert_eq!(
            election.verify(&ballots, &totals),
            Err(VerificationError::WrongCandidates)
        );

        // Change a vote and check it fails.
        totals.insert("Bob", (Scalar::from(1), bob_r_sum).into());
        ballots
            .get_mut("1")
            .unwrap()
            .votes
            .get_mut("Alice")
            .unwrap()
            .R = DreipPoint::identity();
        assert_eq!(
            election.verify(&ballots, &totals),
            Err(VerificationError::Ballot(BallotError::Vote(VoteError {
                ballot_id: "1",
                candidate_id: "Alice",
            })))
        );
    }
}
