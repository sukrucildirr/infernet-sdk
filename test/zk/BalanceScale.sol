// SPDX-License-Identifier: BSD-3-Clause-Clear
pragma solidity ^0.8.4;

import {Attestor} from "./Attestor.sol";
import {InboxItem} from "../../src/Inbox.sol";
import {SubscriptionConsumer} from "../../src/consumer/Subscription.sol";

/// @title BalanceScale
/// @notice E2E developer demo of a balance scale prediction contract
/// @dev Uses simple model trained on UCI balance scale data: https://archive.ics.uci.edu/dataset/12/balance+scale
contract BalanceScale is SubscriptionConsumer {
    /*//////////////////////////////////////////////////////////////
                               IMMUTABLE
    //////////////////////////////////////////////////////////////*/

    /// @notice ZK verifier address
    address internal immutable VERIFIER;

    /// @notice ZK attestor contract
    Attestor internal immutable ATTESTOR;

    /*//////////////////////////////////////////////////////////////
                                MUTABLE
    //////////////////////////////////////////////////////////////*/

    /// @notice Data currently being verified
    /// @dev Used atomically in `_receiveCompute()` callback to remove need for dynamic loading in attestor contract
    int256[4] public currentData;

    /// @notice Subscription ID => associated balance scale weights
    /// @dev format: [right-distance, right-weight, left-distance, left-weight]
    mapping(uint32 => int256[4]) public data;

    /// @notice SubscriptionID => returned prediction output
    /// @dev 0 = scale tipped left, 1 = scale tipped right, 2 = balanced
    mapping(uint32 => int256) public predictions;

    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    /// @notice Thrown if inputs to compute container are recorded incorrectly
    /// @dev 4-byte signature `0x6364fc0e`
    error InputsIncorrect();

    /// @notice Thrown if proof verification fails
    /// @dev 4-byte signature `0xd30ec238`
    error ProofIncorrect();

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /// @notice Initialize new BalanceScale
    /// @param registry registry address
    /// @param verifier ZK verifier address
    /// @param attestor ZK attestor address
    constructor(address registry, address verifier, address attestor) SubscriptionConsumer(registry) {
        // Store verifier address
        VERIFIER = verifier;
        // Initiate attestor contract
        ATTESTOR = Attestor(attestor);
    }

    /*//////////////////////////////////////////////////////////////
                               FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Inherited function: SubscriptionConsumer.getContainerInputs
    function getContainerInputs(uint32 subscriptionId, uint32 interval, uint32 timestamp, address caller)
        external
        view
        override
        returns (bytes memory)
    {
        // Simply return encoded stored input data
        return abi.encode(data[subscriptionId]);
    }

    /// @notice Initiates new prediction by encoding input parameters and kicking off compute request callback
    /// @param input balance scale params: [right-distance, right-weight, left-distance, left-weight]
    /// @param lazy whether to receive response lazily
    function initiatePrediction(int256[4] calldata input, bool lazy) external {
        // Make new subscription creation
        uint32 id = _createComputeSubscription("BSM", 1, 0 minutes, 1, lazy, address(0), 0, address(0), address(0));

        // Store input data
        data[id] = input;
    }

    /// @notice Internal helper to collect instances from proof
    /// @param proof ZK proof
    function _getInstances(bytes calldata proof) external pure returns (int256[] memory) {
        // Proof begins with 4-byte signature to Verifier (because Verifier is staticall'd from Attestor)
        // Thus, we first strip the first 4-bytes of proof to collect just function data
        // Then, we decode the instances array from the stripped proof
        (, int256[] memory instances) = abi.decode(proof[4:proof.length], (bytes, int256[]));
        return instances;
    }

    /// @notice Inherited function: SubscriptionConsumer._receiveCompute
    function _receiveCompute(
        uint32 subscriptionId,
        uint32 interval,
        uint16 redundancy,
        address node,
        bytes calldata input,
        bytes calldata output,
        bytes calldata proof,
        bytes32 containerId,
        uint256 index
    ) internal override {
        // On callback, first, set currentData = relevant data to verify for subscription
        currentData = data[subscriptionId];

        // If response is lazily computed, collect {input, proof} from inbox
        bytes memory input_ = input;
        bytes memory proof_ = proof;
        if (containerId != bytes32(0)) {
            // Collect input, proof
            InboxItem memory item = INBOX.read(containerId, node, index);
            input_ = item.input;
            proof_ = item.proof;
        }

        // Verify off-chain recorded input is correct
        bytes32 hashedInput = keccak256(abi.encode(currentData));
        (bytes32 recordedInput) = abi.decode(input_, (bytes32));
        if (hashedInput != recordedInput) {
            revert InputsIncorrect();
        }

        // Attest + verify proof via attestor
        bool verified = ATTESTOR.verifyWithDataAttestation(VERIFIER, proof_);

        // Error if proof not verified
        if (!verified) {
            revert ProofIncorrect();
        }

        // Set prediction to predicted result from instances array
        // Coeercing bytes memory to bytes calldata
        int256[] memory instances = this._getInstances(proof_);
        predictions[subscriptionId] = int256(instances[instances.length - 1]);
    }
}
