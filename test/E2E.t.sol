// SPDX-License-Identifier: BSD-3-Clause-Clear
pragma solidity ^0.8.4;

import {Test} from "forge-std/Test.sol";
import {Attestor} from "./zk/Attestor.sol";
import {Verifier} from "./zk/Verifier.sol";
import {Registry} from "../src/Registry.sol";
import {LibDeploy} from "./lib/LibDeploy.sol";
import {MockNode} from "./mocks/MockNode.sol";
import {BalanceScale} from "./zk/BalanceScale.sol";

/// @title BalanceScaleTest
/// @notice Tests BalanceScale E2E demo implementation
contract BalanceScaleTest is Test {
    /*//////////////////////////////////////////////////////////////
                                INTERNAL
    //////////////////////////////////////////////////////////////*/

    /// @notice Mock node (Alice)
    MockNode private ALICE;

    /// @notice ZK data attestation contract
    Attestor private ATTESTOR;

    /// @notice BalanceScale demo implementation
    BalanceScale private BALANCE_SCALE;

    /*//////////////////////////////////////////////////////////////
                                 SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public {
        // Deploy contracts
        uint256 initialNonce = vm.getNonce(address(this));
        (Registry registry,,,,,) = LibDeploy.deployContracts(address(this), initialNonce, address(0), 0);

        // Pre-predict expected address of contract(BALANCE_SCALE)
        initialNonce = vm.getNonce(address(this));
        address balanceScaleAddress = vm.computeCreateAddress(address(this), initialNonce + 3);

        // Setup input parameters for attestor contract
        // Contract address to staticcall (our consumer contract, in this case, address(BalanceScale))
        address _contractAddress = balanceScaleAddress;

        // Function calldata to get int256[4] input parameters
        bytes[] memory _calldata = new bytes[](4);
        // We expose the current int256[4] parameters via BalanceScale.currentData
        // We can simply encode the getter function for this public int256[4] state
        bytes4 GETTER_SELECTOR = bytes4(keccak256("currentData(uint256)"));
        for (uint8 i = 0; i < 4; i++) {
            _calldata[i] = abi.encodeWithSelector(GETTER_SELECTOR, i);
        }

        // Initialize new data attestor contract with BalanceScale view-only fn parameters
        ATTESTOR = new Attestor(_contractAddress, _calldata);

        // Deploy generic verifier contract
        Verifier VERIFIER = new Verifier();

        // Setup mock node (ALICE)
        ALICE = new MockNode(registry);

        // Setup balance scale contract
        BALANCE_SCALE = new BalanceScale(address(registry), address(VERIFIER), address(ATTESTOR));

        // Ensure balance scale contract address matches up
        assertEq(address(BALANCE_SCALE), balanceScaleAddress);
    }

    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test E2E flow (push inputs, initiate callback, get response, verify response)
    /// @dev Tests both lazy and eager subscription cases via bool fuzzing
    function testFuzzE2E(bool lazy) public {
        // Setup expected output and inputs
        int256 expectedOutput = 0; // expected result is leaning left (0)
        int256[4] memory inputs = [int256(1), int256(5), int256(2), int256(2)]; // inputs: [1, 5, 2, 2]

        // Setup inputs array as dynamic array for proof generation
        // Append expected output to encoded array
        int256[] memory encoded = new int256[](5);
        for (uint256 i = 0; i < 4; i++) {
            encoded[i] = (inputs[i]);
        }
        encoded[4] = (expectedOutput);

        // Setup proof (exact input to Verifier.verifyProof, including 4-byte signature)
        bytes memory proof = abi.encodeWithSignature("verifyProof(bytes,int256[])", bytes("generic-zk-proof"), encoded);

        // Initiate prediction w/ inputs
        BALANCE_SCALE.initiatePrediction(inputs, lazy);

        // Get new subscription
        uint32 subscriptionId = 1;
        bytes memory containerInputs = BALANCE_SCALE.getContainerInputs(subscriptionId, 0, 0, address(0));
        (int256[4] memory features) = abi.decode(containerInputs, (int256[4]));
        for (uint8 i = 0; i < 4; i++) {
            // Assert features are correctly stored
            assertEq(inputs[i], features[i]);
            // Assert inputs are correctly stored
            assertEq(inputs[i], BALANCE_SCALE.data(subscriptionId, i));
        }

        // Hash recorded container input + prepare for delivery
        bytes32 hashedInput = keccak256(abi.encode(inputs));
        bytes memory input = abi.encode(hashedInput);

        // Submit compute container response from Alice w/ correct proof
        ALICE.deliverCompute(
            subscriptionId, 1, input, "really,any,response,here,we,read,true,output,from,proof", proof, address(0)
        );

        // Assert actual output conforms to expected output
        int256 actualOutput = BALANCE_SCALE.predictions(subscriptionId);
        assertEq(actualOutput, expectedOutput);
    }
}
