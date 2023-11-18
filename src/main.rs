use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::{fs::File, io::prelude::*};

use fhe_auctions::auction_circuit;
use tfhe::{
    core_crypto::entities::LweCiphertext,
    gadget::ciphertext::Ciphertext,
    gadget::{
        client_key::ClientKey, gen_keys, parameters::GadgetParameters, server_key::ServerKey,
    },
    shortint::parameters::{
        CoreCiphertextModulus, DecompositionBaseLog, DecompositionLevelCount, GlweDimension,
        LweDimension, PolynomialSize, StandardDev,
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

    /// A vector of the encrypted values, requires "ciphertext_length"
    #[clap(short = 'e', long = "encryptions", requires = "ciphertext_length")]
    encryptions: Option<Vec<String>>,

    /// The length of the vector of encrypted values, requires "encryptions"
    #[clap(short = 'l', long = "length", requires = "encryptions")]
    ciphertext_length: Option<usize>,

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
    // This means that the bid is a 4 bit number
    let bid_bits_size = 4;
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

        let encryptions: Vec<Vec<Ciphertext>> = if let Some(encryptions) = args.encryptions {
            // Note: we can assume ciphertext length is always present if enc is present due to clap
            serialize_encryptions_from_string(encryptions, args.ciphertext_length.unwrap())
        } else {
            generate_encryptions(&client_key, bid_bits_size)
        };

        dbg!(&encryptions);

        run_auction(&client_key, &encryptions, bid_bits_size);
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
        .expect("Failed to write to file");
    println!("Client key stored successfully");
}

fn read_key() -> ClientKey {
    // Open the file at the specified path
    let mut file =
        File::open("./store/client_key").unwrap_or_else(|_| panic!("Failed to open file"));

    // Read the contents of the file into a string
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .expect("Failed to read file");

    // Deserialize the string into a ClientKey object
    let client_key: ClientKey =
        serde_json::from_str(&contents).expect("Failed to deserialize client key");

    client_key
}

/// In this simple auction example
/// We do not care about having lots of bids
/// We just want to be able to show that you can take two encrypted states
/// and run them together to get a result,
///
/// This will be turned into a little cli that can take in two bids and
/// then declare the winner on their encrypted states

/// The demo path where we encrypt the bids here
fn generate_encryptions(client_key: &ClientKey, bid_bits_size: usize) -> Vec<Vec<Ciphertext>> {
    type BID_BITS_TYPE = u32;
    type EncryptedBid = Vec<Ciphertext>;

    let bids: Vec<BID_BITS_TYPE> = vec![3, 4];

    // TODO: We want an FHE key in the public
    let server_key = ServerKey::new(&client_key);

    // TODO: This will be done in noir
    // we will have to encrypt the bids from
    // encrypt bits from MSB to LSB
    let mut encrypted_bids: Vec<EncryptedBid> = vec![];
    for bid_amount in bids.iter() {
        let mut bid_bits = vec![];
        for i in 0..bid_bits_size {
            let bit_i = (bid_amount >> (bid_bits_size - 1 - i)) & 1;
            let encrypted_bit = client_key.encrypt(bit_i != 0);
            bid_bits.push(encrypted_bit);
        }
        encrypted_bids.push(bid_bits);
    }

    encrypted_bids
}

fn serialize_encryptions_from_string(
    encryptions: Vec<String>,
    ciphertext_length: usize,
) -> Vec<Vec<Ciphertext>> {
    // Convert the serialised encryptions into a vector of ciphertexts

    // NOTE: in this case each encrypted value we receive will contain just the end ciphertext
    // this is as we are going to reuse the same a value for the duration of the hackathon.
    // This harms the security of the scheme, but is fine for demonstration purposes.
    let fixed_a: [u32; 10] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];

    // assert that encryptions is some multiple of ciphertext length, as each bit is encrypted seperately
    assert_eq!(
        encryptions.len() % ciphertext_length,
        0,
        "Encryptions must be a multiple of ciphertext length"
    );

    let ciphertext_modulus = CoreCiphertextModulus::try_new_power_of_2(32).expect("grand");
    let mut encrypted_bids: Vec<Vec<Ciphertext>> = vec![];

    let message_chunks = encryptions.chunks(ciphertext_length);
    for chunk in message_chunks {
        let mut encrypted_bid = vec![];
        for encryption in chunk.iter() {
            // create the encryption as a copy of fixed a with the hex string encryption converted into a u32
            let enc = encryption
                .parse::<u32>()
                .expect("Could not serilaize encryption string");
            let mut ciphertext = fixed_a.clone().to_vec();
            ciphertext.push(enc);

            let e = Ciphertext::Encrypted(LweCiphertext::from_container(
                ciphertext,
                ciphertext_modulus,
            ));
            encrypted_bid.push(e);
        }

        encrypted_bids.push(encrypted_bid);
    }

    encrypted_bids
}

fn run_auction(client_key: &ClientKey, bids: &Vec<Vec<Ciphertext>>, bid_bits: usize) {
    let num_bidders = bids.len();
    let server_key = ServerKey::new(&client_key);
    let (winner_identity_bit, _) =
        auction_circuit(&server_key, &bids, bid_bits, num_bidders).unwrap();

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
}
