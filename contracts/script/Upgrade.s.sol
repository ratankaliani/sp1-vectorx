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
import {SP1Vector} from "../src/SP1Vector.sol";
import {ERC1967Proxy} from "@openzeppelin/proxy/ERC1967/ERC1967Proxy.sol";

contract DeployScript is Script {
    using stdJson for string;

    ISP1Verifier public verifier;

    function setUp() public {}

    function run() public returns (address) {
        vm.startBroadcast();

        bytes32 create2Salt = bytes32(vm.envBytes("CREATE2_SALT"));

        SP1Vector sp1VectorImpl = SP1Vector{salt: bytes32(create2Salt)}(0x0);

        address existingProxyAddress = vm.envAddress("CONTRACT_ADDRESS");
        ERC1967Proxy proxy = ERC1967Proxy(existingProxyAddress);
        proxy.upgradeTo(address(sp1VectorImpl));

        SP1Vector sp1Vector = SP1Vector(address(existingProxyAddress));

        // Update the SP1 Verifier address and the program vkey.
        sp1Vector.updateVerifier(address(verifier));
        sp1Vector.updateVectorXProgramVkey(vm.envBytes32("SP1_VECTOR_PROGRAM_VKEY"));

        return address(existingProxyAddress);
    }
}
