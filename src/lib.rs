pub mod election;
pub mod group;
pub mod pwf;

pub use crate::election::{Ballot, Election, Vote};
pub use crate::pwf::{BallotProof, VoteProof};
#[cfg(feature = "p256_impl")]
pub use p256::NistP256;

#[cfg(all(test, feature = "p256_impl"))]
mod tests {
    use super::*;

    #[test]
    fn test_vote() {
        let mut rng = rand::thread_rng();
        let election = Election::<NistP256>::new(&[b"Test Election"], &mut rng);

        let vote1 = election.create_vote(&mut rng, "1", "Alice", true);
        assert!(vote1.verify(&election, "1", "Alice"));

        let vote2 = election.create_vote(&mut rng, "1", "Bob", false);
        assert!(vote2.verify(&election, "1", "Bob"));

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
        assert!(ballot.verify(&election, "1"));
        assert!(!ballot.verify(&election, "2"));

        // Modify pwf and check it fails.
        ballot.pwf.r[0] += 1;
        assert!(!ballot.verify(&election, "1"));

        // Modify signature and check it fails.
        let mut ballot = election.create_ballot(&mut rng, "2", "Bob",
                                                vec!["Alice, Eve"]).unwrap();
        assert!(ballot.verify(&election, "2"));
        ballot.signature[0] += 1;
        assert!(!ballot.verify(&election, "2"));
    }
}
