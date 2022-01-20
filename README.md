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

The values within `Ballot`s and `Vote`s are exposed in raw byte form, since their precise meaning and structure may depend on the choice of `DreipGroup`.
When using the default `p256` implementation, scalars and curve points are stored using their [SEC1 encodings][sec1];
this means that scalars are big-endian integers, while curve points are big-endian integers with additional metadata at the start.
Private keys are scalars and public keys are curve points, so they follow the same format.
Signatures are two concatenated scalars, `r` followed by `s`.

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
    let ballot = election.create_ballot(
        &mut rng,
        "1234",
        "Alice",
        vec!["Bob", "Eve"]
    ).expect("This can only fail if there are non-unique candidate IDs.");

    // Verify the ballot.
    assert!(ballot.verify(&election, "1234"));

    // Inspect the contents.
    println!("Alice Z value: {:?}", ballot.votes.get("Alice").unwrap().Z);
}
```

## TODO
* Finalise public interface - maybe expose group-specific types instead of raw bytes?

[//]: # (links)
[paper]: https://eprint.iacr.org/2016/670.pdf
[sec1]: https://www.secg.org/sec1-v2.pdf
