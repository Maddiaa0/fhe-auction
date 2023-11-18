use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};

use fhe_auctions::auction_circuit;
use tfhe::{
    gadget::ciphertext::Ciphertext,
    gadget::{boolean::BOOLEAN_PARAMETERS, client_key::ClientKey, gen_keys, server_key::ServerKey},
};

#[derive(Parser)]
#[command(name = "aztec-fhe", author, version, about, long_about = None)]
struct Cli {
    #[clap(short = 's', long = "secret")]
    lwe_secret_key: Option<String>,

    #[clap(subcommand)]
    key_gen: Option<GenKeys>,
}

// Generate a set of fhe keys and write them to std out
// TODO: make sure the params are SMALL!
#[derive(Subcommand, Clone, Debug)]
enum GenKeys {
    KeyGen {},
}

fn main() {
    let args = Cli::parse();

    if args.key_gen.is_some() {
        let (client_key, _server_key) = get_keys();
        let client_str = serde_json::to_string(&client_key)
            .unwrap_or("Could not serialize client key".to_string());

        // TODO: output the client secret key as a long string of zeros,
        // TODO: decrease the parameter length
        println!("Client Key: {}", client_str);
        println!("TODO: serialise and store server key")
    } else {
        println!("deactivated");
        run_simple_auction();
    }
}

fn get_keys() -> (ClientKey, ServerKey) {
    gen_keys(&BOOLEAN_PARAMETERS)
}

/// In this simple auction example
/// We do not care about having lots of bids
/// We just want to be able to show that you can take two encrypted states
/// and run them together to get a result,
///
/// This will be turned into a little cli that can take in two bids and
/// then declare the winner on their encrypted states
fn run_simple_auction() {
    type BID_BITS_TYPE = u32;
    type EncryptedBid = Vec<Ciphertext>;
    let BID_BITS = 32;

    let bidders = 2;

    // TODO: do we need to use 64 or 32 bits
    let BID_BITS = 32;

    let bids: Vec<BID_BITS_TYPE> = vec![1, 2];

    // TODO: We want an FHE key in the public
    let (client_key, server_key) = get_keys();

    // TODO: This will be done in noir
    // we will have to encrypt the bids from
    // encrypt bits from MSB to LSB
    let mut encrypted_bids: Vec<EncryptedBid> = vec![];
    for bid_amount in bids.iter() {
        let mut bid_bits = vec![];
        for i in 0..BID_BITS {
            let bit_i = (bid_amount >> (BID_BITS - 1 - i)) & 1;
            let encrypted_bit = client_key.encrypt(bit_i != 0);
            bid_bits.push(encrypted_bit);
        }
        encrypted_bids.push(bid_bits);
    }

    let (winner_identity_bit, winning_amount_bits) =
        auction_circuit(&server_key, &encrypted_bids, BID_BITS, bidders).unwrap();

    dbg!(winner_identity_bit);
    dbg!(winning_amount_bits);

    // Perform the decryption
}
