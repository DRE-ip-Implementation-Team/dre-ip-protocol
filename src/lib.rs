pub mod election;
pub mod group;
pub mod pwf;

pub use crate::election::{Ballot, Election, Vote};
pub use crate::pwf::{BallotProof, VoteProof};

#[cfg(all(test, feature = "p256_impl"))]
mod tests {
    use super::*;

    use p256::{NistP256, Scalar};
    use std::collections::HashMap;

    use crate::election::{BallotError, VerificationError};
    use crate::group::{DreipScalar, Serializable};

    #[test]
    fn test_vote() {
        let mut rng = rand::thread_rng();
        let election = Election::<NistP256>::new(&[b"Test Election"], &mut rng);

        let vote1 = election.create_vote(&mut rng, "1", "Alice", true);
        assert!(vote1.verify(&election, "1", "Alice").is_ok());

        let vote2 = election.create_vote(&mut rng, "1", "Bob", false);
        assert!(vote2.verify(&election, "1", "Bob").is_ok());

        assert_ne!(vote1.pwf, vote2.pwf);
        assert!(vote2.pwf.verify(&election, &vote1.Z, &vote1.R, "1", "Bob").is_none());
        assert!(vote2.pwf.verify(&election, &vote2.Z, &vote2.R, "2", "Bob").is_none());
        assert!(vote2.pwf.verify(&election, &vote2.Z, &vote2.R, "1", "Alice").is_none());
    }

    #[test]
    fn test_ballot() {
        let mut rng = rand::thread_rng();
        let election = Election::<NistP256>::new(&[b"Woah some random bytes"], &mut rng);

        let mut ballot = election.create_ballot(&mut rng, "1", "Alice",
                                            vec!["Bob", "Eve"]).unwrap();
        assert!(ballot.verify(&election, "1").is_ok());
        match ballot.verify(&election, "2") {
            Err(BallotError::Vote(_)) => {}
            _ => panic!("Assertion failed!")
        }

        // Modify pwf and check it fails.
        ballot.pwf.r = DreipScalar::random(&mut rng);
        assert_eq!(ballot.verify(&election, "1"),
                   Err(BallotError::BallotProof {ballot_id: "1"}));

        // Modify signature and check it fails.
        let mut ballot = election.create_ballot(&mut rng, "2", "Bob",
                                                vec!["Alice", "Eve"]).unwrap();
        assert!(ballot.verify(&election, "2").is_ok());
        let mut sig = ballot.signature.to_bytes();
        sig[0] += 1;
        ballot.signature = Serializable::from_bytes(&sig).unwrap();
        assert_eq!(ballot.verify(&election, "2"),
                Err(BallotError::Signature {ballot_id: "2"}));
    }

    #[test]
    fn test_election() {
        let mut rng = rand::thread_rng();
        let election = Election::<NistP256>::new(&[b"foobaraboof"], &mut rng);
        let mut ballots = HashMap::new();

        ballots.insert("1", election.create_ballot(&mut rng, "1", "Alice",
                                                   vec!["Bob", "Eve"]).unwrap());
        ballots.insert("2", election.create_ballot(&mut rng, "2", "Bob",
                                                   vec!["Alice", "Eve"]).unwrap());
        ballots.insert("3", election.create_ballot(&mut rng, "3", "Alice",
                                                   vec!["Bob", "Eve"]).unwrap());

        let alice_r_sum = ballots.values()
            .map(|b| b.votes.iter().find(|(c, _)| **c == "Alice").unwrap())
            .fold(Scalar::zero(), |a, (_, b)| &a + &b.r);
        let bob_r_sum = ballots.values()
            .map(|b| b.votes.iter().find(|(c, _)| **c == "Bob").unwrap())
            .fold(Scalar::zero(), |a, (_, b)| &a + &b.r);
        let eve_r_sum = ballots.values()
            .map(|b| b.votes.iter().find(|(c, _)| **c == "Eve").unwrap())
            .fold(Scalar::zero(), |a, (_, b)| &a + &b.r);

        let mut totals = HashMap::new();
        totals.insert("Alice", (Scalar::from(2), alice_r_sum));
        totals.insert("Bob", (Scalar::from(1), bob_r_sum));
        totals.insert("Eve", (Scalar::from(0), eve_r_sum));

        assert!(election.verify(&ballots, &totals).is_ok());

        // Now change the tally and check it fails.
        totals.get_mut("Eve").unwrap().0 = Scalar::from(5);
        assert_eq!(election.verify(&ballots, &totals),
                   Err(VerificationError::Tally {candidate_id: "Eve"}));

        // TODO more tests.
    }
}
