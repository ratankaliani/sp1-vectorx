// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/console.sol";
import {Vm} from "forge-std/Vm.sol";
import {StdAssertions} from "forge-std/StdAssertions.sol";
import {Script} from "forge-std/Script.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {SP1Verifier} from "@sp1-contracts/SP1Verifier.sol";
import {SP1MockVerifier} from "@sp1-contracts/SP1MockVerifier.sol";
import {ISP1Verifier} from "@sp1-contracts/ISP1Verifier.sol";
import {VectorX} from "../src/VectorX.sol";
import {ERC1967Proxy} from "@openzeppelin/proxy/ERC1967/ERC1967Proxy.sol";

contract VectorXScript is Script {
    using stdJson for string;

    VectorX public vectorx;
    ISP1Verifier public verifier;

    function setUp() public {}

    function run() public returns (address) {
        vm.startBroadcast();

        // Read trusted initialization parameters from .env
        address guardian = msg.sender;
        uint32 height = uint32(vm.envUint("GENESIS_HEIGHT"));
        bytes32 header = bytes32(vm.envBytes32("GENESIS_HEADER"));
        uint64 authoritySetId = uint64(vm.envUint("GENESIS_AUTHORITY_SET_ID"));
        bytes32 authoritySetHash = bytes32(vm.envBytes32("GENESIS_AUTHORITY_SET_HASH"));
        uint32 headerRangeCommitmentTreeSize = uint32(vm.envUint("HEADER_RANGE_COMMITMENT_TREE_SIZE"));
        bytes32 vectorXProgramVkey = bytes32(vm.envBytes32("VECTORX_PROGRAM_VKEY"));

        // TODO: Detect SP1_PROVER=mock and use a mock verifier if specified.
        VectorX vectorxImpl = new VectorX();
        string memory mockStr = "mock";
        if (keccak256(abi.encodePacked(vm.envString("SP1_PROVER"))) == keccak256(abi.encodePacked(mockStr))) {
            verifier = ISP1Verifier(address(new SP1MockVerifier()));
        } else {
            verifier = ISP1Verifier(address(new SP1Verifier()));
        }
        vectorx = VectorX(address(new ERC1967Proxy(address(vectorxImpl), "")));
        vectorx.initialize(
            VectorX.InitParameters({
                guardian: guardian,
                height: height,
                header: header,
                authoritySetId: authoritySetId,
                authoritySetHash: authoritySetHash,
                headerRangeCommitmentTreeSize: headerRangeCommitmentTreeSize,
                vectorXProgramVkey: vectorXProgramVkey,
                verifier: address(verifier)
            })
        );

        vm.stopBroadcast();

        return address(vectorx);
    }
}
