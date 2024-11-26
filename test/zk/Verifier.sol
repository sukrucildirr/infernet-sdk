// SPDX-License-Identifier: BSD-3-Clause-Clear
pragma solidity ^0.8.4;

/// @title Verifier
/// @notice Mocks generic ZK verifier contract
contract Verifier {
    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    bytes private constant EXPECTED_PROOF = bytes("generic-zk-proof");

    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    /// @notice Thrown by `verifyProof` if proof verification fails
    /// @dev 4-byte signature: `0x439cc0cd`
    error VerificationFailed();

    /*//////////////////////////////////////////////////////////////
                               FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Mocks generic ZK proof verification function
    /// @dev 4-byte signature: `0xb4815d47`
    function verifyProof(bytes calldata proof, int256[] calldata instances) external pure returns (bool) {
        // Verify mock proof
        return keccak256(EXPECTED_PROOF) == keccak256(proof);
    }
}
