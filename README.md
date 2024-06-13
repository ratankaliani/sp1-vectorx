# SP1 Vector X

## Overview

Implementation of [Vector X](https://github.com/succinctlabs/vectorx) in Rust for SP1.

- `/program`: The SP1 VectorX program.
- `/primitives`: Libraries for types and helper functions used in the program.
- `/script`: Scripts for getting the contract's genesis parameters and deploying the operator to 
    update the light client.
- `/contracts`: The contract's source code and deployment scripts. Backwards-compatible with the
    original VectorX implementation in case we need to upgrade.

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

In `/script`, run

```
cargo run --bin script --release
```

## Cycle Count

Header Range
- ~200M cycles. Primarily dominated by Blake2B hashing of the headers in the header range commitment tree.

Rotate
- ~XM cycles.
