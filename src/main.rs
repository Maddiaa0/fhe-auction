use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::{fs::File, io::prelude::*};

use fhe_auctions::auction_circuit;
use tfhe::{
    gadget::ciphertext::Ciphertext,
    gadget::{
        client_key::ClientKey, gen_keys, parameters::GadgetParameters, server_key::ServerKey,
    },
    shortint::parameters::{
        DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
        StandardDev,
    },
};

// Use lower parameters to make iteration easier
pub const BOOLEAN_DEMO: GadgetParameters = GadgetParameters {
    lwe_dimension: LweDimension(10), // Make the a size super small for demo purposes
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(256),
    // This gets raised to the power of 32
    lwe_modular_std_dev: StandardDev(0.000022810107419132102),
    glwe_modular_std_dev: StandardDev(0.00000000037411618952047216),
    pbs_base_log: DecompositionBaseLog(14),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
};

#[derive(Parser)]
#[command(name = "aztec-fhe", author, version, about, long_about = None)]
struct Cli {
    /// Use the stored client key
    #[clap(short = 'r', long = "read_client")]
    read_client: bool,

    #[clap(subcommand)]
    key_gen: Option<GenKeys>,
}

// Generate a set of fhe keys and write them to std out
// TODO: make sure the params are SMALL!
#[derive(Subcommand, Clone, Debug)]
enum GenKeys {
    KeyGen {
        #[clap(short = 's', long = "store")]
        store: bool,
    },
}

fn main() {
    let args = Cli::parse();

    if let Some(GenKeys::KeyGen { store }) = args.key_gen {
        let (client_key, _server_key) = get_keys();
        let client_str = serde_json::to_string(&client_key)
            .unwrap_or("Could not serialize client key".to_string());

        if store {
            store_key(client_key);
        }

        println!("Client Key: {}", client_str);
    } else {
        println!("deactivated");

        let client_key = if args.read_client {
            read_key()
        } else {
            let (client_key, _) = get_keys();
            client_key
        };

        run_simple_auction(client_key);
    }
}

fn get_keys() -> (ClientKey, ServerKey) {
    gen_keys(&BOOLEAN_DEMO)
}

/// Write the client key into storage
/// From this the server key can be derived
/// We want to do this to get the secret key for the user to encrypt with
fn store_key(client_key: ClientKey) {
    // Serialize the client_key using serde's to_vec function
    let client_key_bytes = serde_json::to_vec(&client_key).expect("Failed to serialize client key");

    // Open a file at the specified path
    let _ = std::fs::create_dir_all("./store");
    let mut file = File::create("./store/client_key").expect("Failed to create file");

    // Write the serialized bytes to the file
    file.write_all(&client_key_bytes)
        .unwrap_or_else(|_| panic!("Failed to write to file"));
    println!("Client key stored successfully");
}

fn read_key() -> ClientKey {
    // Open the file at the specified path
    let mut file =
        File::open("./store/client_key").unwrap_or_else(|_| panic!("Failed to open file"));

    // Read the contents of the file into a string
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .unwrap_or_else(|_| panic!("Failed to read file"));

    // Deserialize the string into a ClientKey object
    let client_key: ClientKey = serde_json::from_str(&contents)
        .unwrap_or_else(|_| panic!("Failed to deserialize client key"));

    client_key
}

/// In this simple auction example
/// We do not care about having lots of bids
/// We just want to be able to show that you can take two encrypted states
/// and run them together to get a result,
///
/// This will be turned into a little cli that can take in two bids and
/// then declare the winner on their encrypted states
fn run_simple_auction(client_key: ClientKey) {
    type BID_BITS_TYPE = u32;
    type EncryptedBid = Vec<Ciphertext>;
    let BID_BITS = 32;

    let bidders = 2;

    // NOTE: we are using a fixed a here as a hack,
    // this destroys the security; but it is needed to hackathon velocity

    // TODO: do we need to use 64 or 32 bits
    let BID_BITS = 32;

    let bids: Vec<BID_BITS_TYPE> = vec![3, 4];

    // TODO: We want an FHE key in the public
    let server_key = ServerKey::new(&client_key);

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

    // We use this in the noir context as our a value, and then we can create the cipher text
    let fixed_a: [u32; 10] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];

    let (winner_identity_bit, winning_amount_bits) =
        auction_circuit(&server_key, &encrypted_bids, BID_BITS, bidders).unwrap();

    // dbg!(&winner_identity_bit);

    let mut res_highest_bidder_identity = vec![];
    // TODO: make a function
    winner_identity_bit
        .iter()
        .enumerate()
        .for_each(|(index, bit_ct)| {
            let bit = client_key.decrypt(bit_ct);
            if bit {
                res_highest_bidder_identity.push(index);
            }
        });
    dbg!(res_highest_bidder_identity);
    // dbg!(winning_amount_bits);

    // Perform the decryption
}
