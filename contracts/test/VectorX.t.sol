// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import {VectorX} from "../src/VectorX.sol";
import {TimelockedUpgradeable} from "@succinctx/upgrades/TimelockedUpgradeable.sol";
import {ISP1Verifier} from "@sp1-contracts/ISP1Verifier.sol";
import "forge-std/console.sol";
import {Script} from "forge-std/Script.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {SP1MockVerifier} from "@sp1-contracts/SP1MockVerifier.sol";
import {ERC1967Proxy} from "@openzeppelin/proxy/ERC1967/ERC1967Proxy.sol";

    struct SP1ProofFixtureJson {
        uint32 a;
        uint32 b;
        uint32 n;
        bytes proof;
        bytes publicValues;
        bytes32 vkey;
    }

    struct HeaderRangeOutputs {
        uint32 trusted_block;
        bytes32 trusted_header_hash;
        uint64 authority_set_id;
        bytes32 authority_set_hash;
        uint32 target_block;
        bytes32 target_header_hash;
        bytes32 state_root_commitment;
        bytes32 data_root_commitment;
    }

    struct RotateOutputs {
        uint64 current_authority_set_id;
        bytes32 current_authority_set_hash;
        bytes32 new_authority_set_hash;
    }

    struct ProofOutputs {
        uint8 ProofType;
        bytes HeaderRangeOutputs;
        bytes RotateOutputs;
    }

contract VectorXTest is Test {
    using stdJson for string;
    /// @notice The type of proof that is being verified.
    enum ProofType {
        HeaderRangeProof,
        RotateProof
    }
    VectorX public vectorx;

    function setUp() public {

    }


    function loadFixture() public view returns (SP1ProofFixtureJson memory) {
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/fixtures/fixture.json");
        string memory json = vm.readFile(path);
        bytes memory jsonBytes = json.parseRaw(".");
        return abi.decode(jsonBytes, (SP1ProofFixtureJson));
    }

    function test_Deploy() public {
        // Read trusted initialization parameters from .env
        address guardian = msg.sender;
        uint32 height = uint32(vm.envUint("GENESIS_HEIGHT"));
        bytes32 header = bytes32(vm.envBytes32("GENESIS_HEADER"));
        uint64 authoritySetId = uint64(vm.envUint("GENESIS_AUTHORITY_SET_ID"));
        bytes32 authoritySetHash = bytes32(vm.envBytes32("GENESIS_AUTHORITY_SET_HASH"));
        uint32 headerRangeCommitmentTreeSize = uint32(vm.envUint("HEADER_RANGE_COMMITMENT_TREE_SIZE"));
        bytes32 vectorXProgramVkey = bytes32(vm.envBytes32("VECTORX_PROGRAM_VKEY"));
        SP1MockVerifier verifier = new SP1MockVerifier();

        VectorX vectorxImpl = new VectorX();
        vectorx = VectorX(address(new ERC1967Proxy(
            address(vectorxImpl),
            ""
        )));
        vectorx.initialize(VectorX.InitParameters({
            guardian: guardian,
            height: height,
            header: header,
            authoritySetId: authoritySetId,
            authoritySetHash: authoritySetHash,
            headerRangeCommitmentTreeSize: headerRangeCommitmentTreeSize,
            vectorXProgramVkey: vectorXProgramVkey,
            verifier: address(verifier)
        }));

        console.log("Deployed Address:", address(vectorx));
    }

    function test_Rotate() public {
        test_Deploy();
        vectorx.rotate("", "0x0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000180000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000606b3648f7bf29f5e6d8113ddec2e26bbf8705e7459bedb15e0619778312e9fd8b00ac0925b3544fd394483fe65261944a57198a269d8048a45102df1cd355bd0a");

    }

    function test_AbiDecodeOne() public {
        bytes memory publicValues = hex"0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000180000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000606b3648f7bf29f5e6d8113ddec2e26bbf8705e7459bedb15e0619778312e9fd8b00ac0925b3544fd394483fe65261944a57198a269d8048a45102df1cd355bd0a";
        console.log("trying to decode public values in test");

        (uint8 proofTypeInt, bytes memory headerRangeOutputs, bytes memory rotateOutputs) = abi.decode(publicValues, (uint8, bytes, bytes));
        console.log("trying to decode rotate output in test");
        // rotate
        (uint64 _currentAuthoritySetId, bytes32 currentAuthoritySetHash, bytes32 newAuthoritySetHash) =
                            abi.decode(rotateOutputs, (uint64, bytes32, bytes32));


    }

    function test_AbiDecodeEndToEnd() public {
        HeaderRangeOutputs memory headerRangeOutputs = HeaderRangeOutputs({
            trusted_block: 272355,
            trusted_header_hash: 0x4c8dd5e52e2d3a01f0228070d6c6ec557304c1a71b21a8de344ed5f9de858879,
            authority_set_id: 84,
            authority_set_hash: 0xba873a3572cc2e019a5ec10182716aea73325906882194b9d3a19fc0408834e8,
            target_block: 272534,
            target_header_hash: 0xbc4b14a9759ff3ba227179419129f719ee9ed33894e6a1f1edc300954f63f48b,
            state_root_commitment: 0x7f48a4428b18e80a47eaf92880dd048a79bd1d4161a3a5b5edb67b97c525972a,
            data_root_commitment: 0x13ab31250cb9b3890c436541c1fa081622b5117fdca36fe88a8ae8bf6d852bb0
        });

        RotateOutputs memory rotateOutputs = RotateOutputs({
            current_authority_set_id: 96,
            current_authority_set_hash: 0x6b3648f7bf29f5e6d8113ddec2e26bbf8705e7459bedb15e0619778312e9fd8b,
            new_authority_set_hash: 0x00ac0925b3544fd394483fe65261944a57198a269d8048a45102df1cd355bd0a
        });

        console.log("Asserting header range encoded bytes are equal");
        bytes memory headerRangeOutputsBytes = abi.encode(headerRangeOutputs);
        bytes memory rustHeaderRangeOutputsBytes = hex"00000000000000000000000000000000000000000000000000000000000427e34c8dd5e52e2d3a01f0228070d6c6ec557304c1a71b21a8de344ed5f9de8588790000000000000000000000000000000000000000000000000000000000000054ba873a3572cc2e019a5ec10182716aea73325906882194b9d3a19fc0408834e80000000000000000000000000000000000000000000000000000000000042896bc4b14a9759ff3ba227179419129f719ee9ed33894e6a1f1edc300954f63f48b7f48a4428b18e80a47eaf92880dd048a79bd1d4161a3a5b5edb67b97c525972a13ab31250cb9b3890c436541c1fa081622b5117fdca36fe88a8ae8bf6d852bb0";
        assertEq(headerRangeOutputsBytes, rustHeaderRangeOutputsBytes);

        console.log("Asserting rotate encoded bytes are equal");
        bytes memory rotateOutputsBytes = abi.encode(rotateOutputs);
        bytes memory rustRotateOutputsBytes = hex"00000000000000000000000000000000000000000000000000000000000000606b3648f7bf29f5e6d8113ddec2e26bbf8705e7459bedb15e0619778312e9fd8b00ac0925b3544fd394483fe65261944a57198a269d8048a45102df1cd355bd0a";
        assertEq(rotateOutputsBytes, rustRotateOutputsBytes);

        console.log("Asserting header range proofs are equal");
        bytes memory rotatePadding = hex"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
        bytes memory headerRangeProofOutput = abi.encode(ProofOutputs({
            ProofType: uint8(ProofType.HeaderRangeProof),
            HeaderRangeOutputs: headerRangeOutputsBytes,
            RotateOutputs: rotatePadding
        }));
        bytes memory rustHeaderRangeProofOutput = hex"0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000180000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000427e34c8dd5e52e2d3a01f0228070d6c6ec557304c1a71b21a8de344ed5f9de8588790000000000000000000000000000000000000000000000000000000000000054ba873a3572cc2e019a5ec10182716aea73325906882194b9d3a19fc0408834e80000000000000000000000000000000000000000000000000000000000042896bc4b14a9759ff3ba227179419129f719ee9ed33894e6a1f1edc300954f63f48b7f48a4428b18e80a47eaf92880dd048a79bd1d4161a3a5b5edb67b97c525972a13ab31250cb9b3890c436541c1fa081622b5117fdca36fe88a8ae8bf6d852bb00000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
        assertEq(headerRangeProofOutput, rustHeaderRangeProofOutput);

        console.log("Asserting rotate proofs are equal");
        bytes memory headerRangePadding = hex"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
        bytes memory rotateProofOutput = abi.encode(ProofOutputs({
            ProofType: uint8(ProofType.RotateProof),
            HeaderRangeOutputs: headerRangePadding,
            RotateOutputs: rotateOutputsBytes
        }));
        bytes memory rustRotateProofOutput = hex"0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000180000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000606b3648f7bf29f5e6d8113ddec2e26bbf8705e7459bedb15e0619778312e9fd8b00ac0925b3544fd394483fe65261944a57198a269d8048a45102df1cd355bd0a";
        assertEq(rotateProofOutput, rustRotateProofOutput);

        // Decode encoded proof outputs
        console.log("Decoding rotate ProofOutput");
        (uint8 proofTypeIntRotate,, bytes memory decodedProofOutputs) = abi.decode(rotateProofOutput, (uint8, bytes, bytes));
        console.log("Decoding rotate outputs from ProofOutput");
        (uint64 _currentAuthoritySetId, bytes32 currentAuthoritySetHash, bytes32 newAuthoritySetHash) =
                            abi.decode(decodedProofOutputs, (uint64, bytes32, bytes32));

        console.log("Decoding header range ProofOutput");
        (uint8 proofTypeIntHeaderRange, bytes memory decodedHeaderRangeOutputs,) = abi.decode(headerRangeProofOutput, (uint8, bytes, bytes));
        console.log("Decoding header range outputs from ProofOutput");
        (uint32 trusted_block, bytes32 trusted_header_hash, uint64 authority_set_id, bytes32 authority_set_hash, uint32 target_block, bytes32 target_header_hash, bytes32 state_root_commitment, bytes32 data_root_commitment) =
                            abi.decode(decodedHeaderRangeOutputs, (uint32, bytes32, uint64, bytes32, uint32, bytes32, bytes32, bytes32));
    }

    function test_AbiDecode2() public {
        SP1ProofFixtureJson memory fixture = loadFixture();
        bytes memory bla = hex"00000000000000000000000000000000000000000000000000000000000001f400000000000000000000000000000000000000000000000000000000000004f40000000000000000000000000000000000000000000000000000000000000786";
        console.log("bla length:", bla.length);
        console.log(fixture.publicValues.length);
        (uint32 n, uint32 a, uint32 b) = abi.decode(
            bla,
            (uint32, uint32, uint32)
        );
    }
}

