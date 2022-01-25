use std::fs::File;
use std::io::BufReader;

use clap::Parser;

use dre_ip::ElectionResults;
use dre_ip::election::{BallotError, VerificationError, VoteError};

// Treat ballot and candidate IDs as strings, and use the NIST-P256 elliptic curve.
type BallotId = String;
type CandidateId = String;
type Group = dre_ip::group::p256::NistP256;

/// Shown in the help message.
const ABOUT_TEXT: &str =
"Verify the integrity of a DRE-ip election using the P256 elliptic curve.

Exit codes:
     0: Success
   255: Ran successfully, but election failed to verify.
 Other: Error";

/// The CLI arguments to parse.
#[derive(Debug, Parser)]
#[clap(name = "verify-election", author, version,
       about = ABOUT_TEXT, long_about = None)]
struct Args {
    /// The JSON election dump to verify.
    file: String,
}

/// Errors that this program may produce.
#[derive(Debug, Eq, PartialEq)]
enum Error {
    /// IO error described by the inner message.
    IO(String),
    /// Failed to decode the election dump.
    Format,
    /// Verification failed for the described reason.
    Verification(VerificationError<BallotId, CandidateId>),
}

fn main() {
    fn run() -> Result<(), Error> {
        // Try to load the file.
        let args: Args = Args::parse();
        let file = File::open(&args.file)
            .map_err(|e| Error::IO(e.to_string()))?;
        // Try to read the election dump.
        let election: ElectionResults<BallotId, CandidateId, Group> =
            serde_json::from_reader(BufReader::new(file))
                .map_err(|_| Error::Format)?;
        // Verify the election.
        election.verify().map_err(|e| Error::Verification(e))
    }

    let exit_code: u8 = match run() {
        Ok(()) => {
            println!("Election successfully verified.");
            0
        }
        Err(Error::IO(msg)) => {
            println!("IO error: {}", msg);
            1
        }
        Err(Error::Format) => {
            println!("Invalid election dump.");
            1
        }
        Err(Error::Verification(err)) => {
            let msg = match err {
                VerificationError::Ballot(err) => {
                    match err {
                        BallotError::Vote(VoteError {ballot_id, candidate_id}) => {
                            format!("Ballot {} has an invalid vote for candidate {}.",
                                    ballot_id, candidate_id)
                        }
                        BallotError::BallotProof {ballot_id} => {
                            format!("Ballot {} has an invalid proof of well-formedness.",
                                    ballot_id)
                        }
                        BallotError::Signature {ballot_id} => {
                            format!("Ballot {} has an invalid signature.", ballot_id)
                        }
                    }
                }
                VerificationError::Tally {candidate_id} => {
                    format!("The tally for candidate {} is incorrect.", candidate_id)
                }
                VerificationError::WrongCandidates => {
                    String::from("The candidates listed in the tallies do \
                    not match those found in the ballots.")
                }
            };
            println!("Election failed to verify: {}", msg);
            255
        }
    };

    std::process::exit(exit_code.into())
}
