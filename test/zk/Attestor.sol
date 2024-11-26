// SPDX-License-Identifier: BSD-3-Clause-Clear
pragma solidity ^0.8.4;

/// @title Attestor
/// @notice Mocks generic ZK data attestation contract
contract Attestor {
    /*//////////////////////////////////////////////////////////////
                                INTERNAL
    //////////////////////////////////////////////////////////////*/

    /// @notice Target contract (to verify inputs against)
    address private TARGET;

    /// @notice Execution calldata (to retrieve attested inputs)
    bytes[] private DATA;

    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    /// @notice Thrown by `verifyWithDataAttestation` if low-level staticcall fails
    /// @dev 4-byte signature: `0xe10bf1cc`
    error StaticCallFailed();

    /// @notice Thrown by `verifyWithDataAttestation` if input attestation fails
    /// @dev 4-byte signature: `0x63d70518`
    error AttestationFailed();

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /// @notice Initializes new Attestor
    /// @param target target contract (to verify inputs against)
    /// @param data execution calldata (to retrieve attested inputs)
    constructor(address target, bytes[] memory data) {
        TARGET = target;
        for (uint256 i = 0; i < data.length; i++) {
            DATA.push(data[i]);
        }
    }

    /*//////////////////////////////////////////////////////////////
                               FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Attests proof data, then calls verifier
    /// @param verifier verifier to call
    /// @param encoded encoded proof data
    /// @return Proof verification status
    function verifyWithDataAttestation(address verifier, bytes calldata encoded) external view returns (bool) {
        // Decode {attested inputs} from encoded proof data
        (, int256[] memory instances) = abi.decode(encoded[4:encoded.length], (bytes, int256[]));

        // Verify attested inputs match current inputs in target contract
        bool success;
        bytes memory data;
        for (uint256 i = 0; i < DATA.length; i++) {
            int256 attestedData = instances[i];

            // Staticcall target to collect actual data
            (success, data) = TARGET.staticcall(DATA[i]);
            if (!success) {
                revert StaticCallFailed();
            }

            // Decode actual data
            int256 actualData = abi.decode(data, (int256));

            // Assert attested input
            if (actualData != attestedData) {
                revert AttestationFailed();
            }
        }

        // Staticcall relevant verifier
        (success, data) = verifier.staticcall(encoded);
        if (!success) {
            revert StaticCallFailed();
        }
        bool status = abi.decode(data, (bool));
        return status;
    }
}
