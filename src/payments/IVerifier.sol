// SPDX-License-Identifier: BSD-3-Clause-Clear
pragma solidity ^0.8.4;

/// @title IVerifier
/// @notice Basic interface for verifier contracts to: (1) expose verification fees and `Wallet` address, (2) expose function to begin proof verification journey
interface IVerifier {
    /// @notice Gets verifier contract's associated `Wallet` address
    /// @dev Does not necessarily have to conform to the exact `Wallet` spec. since this address does not need to authorize the coordinator for spend
    /// @return `Wallet` address to receive proof verification payment
    function getWallet() external view returns (address);

    /// @notice Checks if `token` is accepted payment method by verifier contract
    /// @param token token address
    /// @return `true` if `token` is supported, else `false`
    function isSupportedToken(address token) external view returns (bool);

    /// @notice Gets proving fee denominated in `token`
    /// @dev Function `isSupportedToken` is called first
    /// @param token token address
    /// @return proving fee denominated in `token`
    function fee(address token) external view returns (uint256);

    /// @notice Request proof verification from verification contract
    /// @dev Verifiers should restrict this function to being called only by `address(COORDINATOR)` to prevent DoS misuse
    /// @dev Verifier contract has to call `verifyProof` on coordinator after a proof verification request
    /// @dev By this point, verifier contract has been paid for proof verification
    /// @param subscriptionId subscription ID
    /// @param interval subscription response interval
    /// @param node response submitting node
    /// @param proof provided response proof bytes
    function requestProofVerification(uint32 subscriptionId, uint32 interval, address node, bytes calldata proof)
        external;

    /// @notice Enforce ETH deposits to `IVerifier`-implementing contract
    /// @dev A verifier may still choose to not support ETH by returning `false` for `isSupportedToken(address(0))`
    receive() external payable;
}
