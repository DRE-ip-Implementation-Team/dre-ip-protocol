use std::collections::HashMap;

use p256::NistP256;
use rand::Rng;

use dre_ip::group::Serializable;
use dre_ip::{Ballot, CandidateTotals, Election};

fn main() {
    let mut rng = rand::thread_rng();
    const CANDIDATES: &[&str] = &["Alice", "Bob", "Eve"];
    const BALLOTS: &[&str] = &["0", "1", "2", "3", "4"];
    const AUDITS: &[&str] = &["5", "6", "7", "8", "9"];

    // Create a new election.
    let election = Election::<NistP256>::new(&[b"Hello, World!"], &mut rng);
    let mut audited = HashMap::new();
    let mut confirmed = HashMap::new();
    let mut totals = HashMap::with_capacity(CANDIDATES.len());
    for candidate in CANDIDATES {
        totals.insert(*candidate, CandidateTotals::default());
    }

    // Create and confirm ballots.
    for ballot_id in BALLOTS {
        // Pick a random candidate to vote for.
        let candidate_index = rng.gen_range(0..CANDIDATES.len());
        let yes_candidate = CANDIDATES[candidate_index];
        let no_candidates = CANDIDATES.iter().enumerate().filter_map(|(i, c)| {
            if i != candidate_index {
                Some(*c)
            } else {
                None
            }
        });

        // Create the ballot.
        let ballot = Ballot::<_, NistP256, _>::new(
            &mut rng,
            election.g1,
            election.g2,
            *ballot_id,
            yes_candidate,
            no_candidates,
        )
        .unwrap();

        // Confirm the ballot, adding the secrets to the totals.
        let mut totals_mut = totals
            .iter_mut()
            .map(|(id, t)| (*id, t))
            .collect::<HashMap<_, _>>();
        let ballot = ballot.confirm(Some(&mut totals_mut));
        confirmed.insert(*ballot_id, ballot);
    }

    // Now create some audited ballots.
    for ballot_id in AUDITS {
        // Pick a random candidate to vote for.
        let candidate_index = rng.gen_range(0..CANDIDATES.len());
        let yes_candidate = CANDIDATES[candidate_index];
        let no_candidates = CANDIDATES.iter().enumerate().filter_map(|(i, c)| {
            if i != candidate_index {
                Some(*c)
            } else {
                None
            }
        });

        // Create the ballot.
        let ballot = Ballot::<_, NistP256, _>::new(
            &mut rng,
            election.g1,
            election.g2,
            *ballot_id,
            yes_candidate,
            no_candidates,
        )
        .unwrap();
        audited.insert(*ballot_id, ballot);
    }

    // Verify the election.
    assert!(dre_ip::verify_election(election.g1, election.g2, &confirmed, &totals).is_ok());
    for (id, ballot) in audited.iter() {
        assert!(ballot.verify(election.g1, election.g2, id).is_ok());
    }
    println!("Election successfully verified.");

    // Announce the results.
    println!("Results:");
    for (candidate, candidate_totals) in totals.iter() {
        println!(
            "{}: {} votes",
            candidate,
            scalar_to_u64(&candidate_totals.tally).unwrap()
        );
    }
}

fn scalar_to_u64<S: Serializable>(scalar: &S) -> Option<u64> {
    const SIZE: usize = std::mem::size_of::<u64>();

    let bytes: Vec<u8> = scalar
        .to_bytes()
        .into_iter()
        .skip_while(|b| b == &0)
        .collect();
    if bytes.len() > SIZE {
        return None;
    }

    let mut u64_bytes = [0; SIZE];
    let start = SIZE - bytes.len();
    u64_bytes[start..SIZE].clone_from_slice(&bytes[..(SIZE - start)]);

    Some(u64::from_be_bytes(u64_bytes))
}
