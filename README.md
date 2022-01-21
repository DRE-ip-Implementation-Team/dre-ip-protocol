# dre-ip
###### An implementation of the DRE-ip voting protocol as per the paper by Shahandashti and Hao.

## Overview
This crate provides an implementation of the [DRE-ip voting protocol][paper].
It is generic over a suitable group via the `DreipGroup` trait;
an implementation is provided for the `NIST P-256` elliptic curve via the default `p256_impl` feature.

The core interface consists of the `Election`, `Ballot`, and `Vote` structs.
An `Election` is parameterised by a `DreipGroup` implementation and holds the global election data: generators and keys.
It provides methods to create ballots and votes.

A `Ballot` represents a yes vote for exactly one candidate across a set of candidates, using the parallel-systems method of multiple candidate encoding (see [section 6 of the paper][paper]).
It contains multiple `Vote`s, each of which represents a single yes or no vote for a single candidate.

## Example Usage

```rust
fn example() {
    let mut rng = rand::thread_rng();

    // Create an election.
    let election = Election::<NistP256>::new(
        &[b"Hello, World!"],
        &mut rng
    );

    // Create a ballot.
    const BALLOT_ID: &str = "1234";
    let ballot = election.create_ballot(
        &mut rng,
        BALLOT_ID,
        "Alice",
        vec!["Bob", "Eve"]
    ).expect("This can only fail if there are non-unique candidate IDs.");

    // Verify the ballot.
    assert!(ballot.verify(&election, BALLOT_ID));

    // Inspect the contents.
    println!("Alice Z value: {:?}", ballot.votes.get("Alice").unwrap().Z);
}
```

[//]: # (links)
[paper]: https://eprint.iacr.org/2016/670.pdf
[sec1]: https://www.secg.org/sec1-v2.pdf
