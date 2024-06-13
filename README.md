# SP1 Vector X

Primitives will contain the libraries for types as well as common functions used in verification which include:

1. Verifying signatures.
2. Decoding the header.
3. Constructing and verifyingthe authority set hash.
4. How expensive would it be to do hashing inside of the program?

## Run the VectorX Light Client

Get the genesis parameters for the `VectorX` contract.

```
cargo run --bin genesis
```

Update `contracts/.env` following `contracts/README.md`.

Deploy the `VectorX` contract with genesis parameters.

In `contracts/`, run

```
forge install

source .env

forge script script/VectorX.s.sol --rpc-url $RPC_URL --private-key $PRIVATE_KEY --etherscan-api-key $ETHERSCAN_API_KEY --broadcast --verify
```

Update `.env` following `.env.example`.

Run `VectorX` script to update the LC continuously.

In `/`, run

```
cargo run --bin vectorx
```

## Cycle Count

The rough cycle count of SP1 VectorX is ~200M cycles.
