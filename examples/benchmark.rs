use std::collections::HashMap;
use std::io::Write;
use std::time::{Duration, Instant};

use p256::NistP256;
use rand::Rng;

use dre_ip::{Ballot, CandidateTotals, DreipPrivateKey, DreipPublicKey, Election};

#[rustfmt::skip]
const CANDIDATES: [&str; 16] = [
    "Alice",
    "Bob",
    "Carol",
    "Dave",
    "Eve",
    "Fred",
    "Grace",
    "Harry",
    "Irene",
    "Joe",
    "Katie",
    "Leon",
    "Mary",
    "Noel",
    "Orah",
    "Pete",
];

const NUM_CONFIRM: usize = 9800;
const NUM_AUDIT: usize = 200;
const NUM_VOTES: usize = NUM_CONFIRM + NUM_AUDIT;

fn main() {
    let mut rng = rand::thread_rng();
    let election = Election::<NistP256>::new(&[b"benchmark"], &mut rng);
    let mut audited = HashMap::new();
    let mut confirmed = HashMap::new();
    let mut totals = HashMap::with_capacity(CANDIDATES.len());
    for candidate in CANDIDATES {
        totals.insert(candidate, CandidateTotals::default());
    }

    // Create ballots.
    let mut encrypt_dur = Duration::ZERO;
    let mut candidate_zkp_dur = Duration::ZERO;
    let mut ballot_zkp_dur = Duration::ZERO;

    // Create confirmed ballots.
    for i in 0..NUM_CONFIRM {
        let ballot_id = i.to_string();

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
        let (ballot, ed, czd, bzd) = Ballot::<_, NistP256, _>::new(
            &mut rng,
            election.g1,
            election.g2,
            ballot_id.as_str(),
            yes_candidate,
            no_candidates,
        )
        .unwrap();

        encrypt_dur += ed;
        candidate_zkp_dur += czd;
        ballot_zkp_dur += bzd;

        // Confirm the ballot, adding the secrets to the totals.
        let mut totals_mut = totals
            .iter_mut()
            .map(|(id, t)| (*id, t))
            .collect::<HashMap<_, _>>();
        let ballot = ballot.confirm(Some(&mut totals_mut));
        confirmed.insert(ballot_id, ballot);

        let num_done = i + 1;
        if num_done % (NUM_VOTES / 100) == 0 {
            let done = num_done as f32 / NUM_VOTES as f32 * 100.0;
            print!("\r{:.0}% cast", done);
            std::io::stdout().flush().unwrap();
        }
    }

    // Create audited ballots.
    for i in NUM_CONFIRM..NUM_VOTES {
        let ballot_id = i.to_string();

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
        let (ballot, ed, czd, bzd) = Ballot::<_, NistP256, _>::new(
            &mut rng,
            election.g1,
            election.g2,
            ballot_id.as_str(),
            yes_candidate,
            no_candidates,
        )
        .unwrap();

        encrypt_dur += ed;
        candidate_zkp_dur += czd;
        ballot_zkp_dur += bzd;

        audited.insert(ballot_id, ballot);

        let num_done = i + 1;
        if num_done % (NUM_VOTES / 100) == 0 {
            let done = num_done as f32 / NUM_VOTES as f32 * 100.0;
            print!("\r{:.0}% cast", done);
            std::io::stdout().flush().unwrap();
        }
    }

    println!("\n\n== {} ballot creation ==", NUM_VOTES);
    println!(
        "Encryption time:    {:12.8}s (AVG {:6.0}µs)",
        encrypt_dur.as_secs_f64(),
        encrypt_dur.as_secs_f64() * 1000000.0 / NUM_VOTES as f64,
    );
    println!(
        "Candidate ZKP time: {:12.8}s (AVG {:6.0}µs)",
        candidate_zkp_dur.as_secs_f64(),
        candidate_zkp_dur.as_secs_f64() * 1000000.0 / NUM_VOTES as f64,
    );
    println!(
        "Ballot ZKP time:    {:12.8}s (AVG {:6.0}µs)",
        ballot_zkp_dur.as_secs_f64(),
        ballot_zkp_dur.as_secs_f64() * 1000000.0 / NUM_VOTES as f64,
    );

    // Verify.
    println!("\nVerifying...");
    let (mut candidate_zkp_ver, mut ballot_zkp_ver, tally_ver) =
        dre_ip::verify_election(election.g1, election.g2, &confirmed, &totals).unwrap();
    for (id, ballot) in audited.iter() {
        let (vd, pd) = ballot.verify(election.g1, election.g2, id).unwrap();
        candidate_zkp_ver += vd;
        ballot_zkp_ver += pd;
    }

    // Approximate signature verification time.
    let mut signature_ver = Duration::ZERO;
    for (id, ballot) in confirmed.iter() {
        // Verification time is forming the bytes plus the verification op.
        // Since we need the bytes to form the signature in the first place, time the two
        // separately.
        let start = Instant::now();
        let mut data = ballot.to_bytes();
        data.extend(id.as_bytes());
        data.extend(b"fake election ID");
        data.extend(b"fake question ID");
        data.extend(b"fake confirmation code");
        signature_ver += start.elapsed();

        let sig = election.private_key.sign(&data);

        let start = Instant::now();
        assert!(election.public_key.verify(&data, &sig));
        signature_ver += start.elapsed();
    }

    println!("\n== {} ballot verification ==", NUM_VOTES);
    println!(
        "Candidate ZKP time: {:12.8}s (AVG {:6.0}µs)",
        candidate_zkp_ver.as_secs_f64(),
        candidate_zkp_ver.as_secs_f64() * 1000000.0 / NUM_VOTES as f64,
    );
    println!(
        "Ballot ZKP time:    {:12.8}s (AVG {:6.0}µs)",
        ballot_zkp_ver.as_secs_f64(),
        ballot_zkp_ver.as_secs_f64() * 1000000.0 / NUM_VOTES as f64,
    );
    println!(
        "Signature time:     {:12.8}s (AVG {:6.0}µs)",
        signature_ver.as_secs_f64(),
        signature_ver.as_secs_f64() * 1000000.0 / NUM_VOTES as f64,
    );
    println!(
        "Tally time:         {:12.8}s (AVG {:6.0}µs)",
        tally_ver.as_secs_f64(),
        tally_ver.as_secs_f64() * 1000000.0 / NUM_VOTES as f64,
    );
}
