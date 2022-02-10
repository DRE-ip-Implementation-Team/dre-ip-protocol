use std::collections::HashMap;
use std::fs::File;
use std::io::BufWriter;

use p256::NistP256;
use rand::Rng;

use dre_ip::{Election, ElectionResults};
use dre_ip::group::Serializable;

fn main() {
    let mut rng = rand::thread_rng();
    const CANDIDATES: &[&str] = &["Alice", "Bob", "Eve"];
    const BALLOTS: &[&str] = &["0", "1", "2", "3", "4"];

    // Create a new election.
    let election = Election::<NistP256>::new(&[b"Hello, World!"], &mut rng);
    let mut ballots = HashMap::new();
    let mut totals = HashMap::with_capacity(CANDIDATES.len());

    // Create and confirm ballots.
    for ballot_id in BALLOTS {
        // Pick a random candidate to vote for.
        let candidate_index = rng.gen_range(0..CANDIDATES.len());
        let yes_candidate = CANDIDATES[candidate_index];
        let no_candidates = CANDIDATES.iter()
            .enumerate()
            .filter_map(|(i, c)| if i != candidate_index {Some(*c)} else {None});

        // Create the ballot.
        let ballot = election.create_ballot(&mut rng, *ballot_id,
                                            yes_candidate, no_candidates).unwrap();

        // Confirm the ballot, adding the secrets to the totals.
        let ballot = ballot.confirm(Some(&mut totals));
        ballots.insert(*ballot_id, ballot);
    }

    // Verify the election.
    let results = ElectionResults {
        election,
        ballots,
        totals,
    };
    assert!(results.verify().is_ok());

    // Announce the results.
    println!("Results:");
    for (candidate, candidate_totals) in results.totals.iter() {
        println!("{}: {} votes", candidate, scalar_to_u64(&candidate_totals.tally).unwrap());
    }

    // Dump it to a file.
    let mut output = BufWriter::new(File::create("election.json").unwrap());
    serde_json::to_writer_pretty(&mut output, &results).unwrap();
}

fn scalar_to_u64<S: Serializable>(scalar: &S) -> Option<u64> {
    const SIZE: usize = std::mem::size_of::<u64>();

    let bytes: Vec<u8> = scalar.to_bytes().into_iter()
        .skip_while(|b| b == &0)
        .collect();
    if bytes.len() > SIZE {
        return None;
    }

    let mut u64_bytes = [0; SIZE];
    let start = SIZE - bytes.len();
    for i in start..SIZE {
        u64_bytes[i] = bytes[i - start];
    }

    Some(u64::from_be_bytes(u64_bytes))
}