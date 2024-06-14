# SP1 Vector X

## Overview

Implementation of [Vector X](https://github.com/succinctlabs/vectorx) in Rust for SP1.

- `/program`: The SP1 VectorX program.
- `/primitives`: Libraries for types and helper functions used in the program.
- `/script`: Scripts for getting the contract's genesis parameters and deploying the operator to 
    update the light client.
- `/services`: RPC fetcher for the `script` + the justification indexer.
- `/contracts`: The contract's source code and deployment scripts. 
- `/query`: Contains the logic for querying data root proofs from the contracts. Automatically deploys to https://vectorx-query.succinct.xyz.

## Demo Contract

An example contract using SP1 VectorX can be found on Sepolia [here](https://sepolia.etherscan.io/address/0x745B0a27F125Faa85BBe743f918c3741E2832236).

## Run the VectorX Light Client

Get the genesis parameters for the `VectorX` contract.

```
cd script

cargo run --bin genesis --release
```

Update `contracts/.env` following `contracts/README.md`.

Deploy the `VectorX` contract with genesis parameters.

In `contracts/`, run

```
forge install

source .env

forge script script/VectorX.s.sol --rpc-url $RPC_URL --private-key $PRIVATE_KEY --etherscan-api-key $ETHERSCAN_API_KEY --broadcast --verify
```

Update `script/.env` following `script/.env.example`.

Run `VectorX` script to update the LC continuously.


```
cd script

cargo run --bin operator --release
```

### Run with Docker

Build the Docker container.
```sh
docker build -t sp1-vectorx-operator -f Dockerfile.operator .
```

```sh
bash run_operator.sh
```

## [Query Data Root Proofs](./query/README.md)

## Cycle Count

Header Range
- Dominated by Blake2B hashing of the headers in the header range commitment tree.

Rotate
- ~8M cycles.
