# FHE auctions

Implements bit slice approach for private auctions as described in [2002/189](https://eprint.iacr.org/2002/189).

Uses [tfhe-rs](https://github.com/zama-ai/tfhe-rs) to implement boolean gates using p-encoding technique as described in [2023/1589](https://eprint.iacr.org/2023/1589.pdf).

<s>TFHE parameters are obtained via concrete-optimiser and has 128-bit of security.</s> The parameters in this fork are NOT secure.

# Costs

Auction circuit runtime increase linearly with $k$ and $n$, where $n$ is no. of bidders and $k$ is bits in bid (for ex, 64 bits, 128 bits)

Since a bid of $k$ bits is represented as $k$ LWE ciphertexts, each bidder needs to upload $k$ LWE ciphertexts.

# Installation 
```
cargo install --path .
```

# Command Line Interface 
```
Usage: fhe-auctions [OPTIONS] [COMMAND]

Commands:
  key-gen
  help     Print this message or the help of the given subcommand(s)

Options:
  -r, --read_client                 Use the stored client key
  -e, --encryptions <ENCRYPTIONS>   A vector of the encrypted values, requires "ciphertext_length"
  -l, --length <CIPHERTEXT_LENGTH>  The length of the vector of encrypted values, requires "encryptions"
  -h, --help                        Print help
  -V, --version                     Print version
```

# Test

On x86_64 based machines set `tfhe-rs` dependecy in cargo.toml as

`tfhe = {git = "https://github.com/Janmajayamall/tfhe-rs.git", features = ["boolean", "shortint", "integer", "p-encoding","x86_64-unix"]}`

On apple-silicon or aarch-64 based machines set `tfhe-rs` dependecy in cargo.toml as

`tfhe = {git = "https://github.com/Janmajayamall/tfhe-rs.git", features = ["boolean", "shortint", "integer", "p-encoding","aarch64-unix"]}`

then run `cargo test --release tests::auction_circuit_works -- --nocapture`
