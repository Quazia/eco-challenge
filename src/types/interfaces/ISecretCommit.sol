// SPDX-License-Identifier: Unlicense
pragma solidity 0.8.19;
import {Secret} from "src/types/structs/Secret.sol";

interface ISecretCommit {
    event Reveal(bytes indexed secret, address indexed revealer);

    /// @notice Commits two parties to a secret by storing their signatures in a single block
    /// @param hashSecret Hash of the secret we want to commit to
    /// @param v1 Final byte of the signature of the first signer
    /// @param r1 First 32 bytes of the signature of the first signer
    /// @param s1 Second 32 bytes of the signature of the first signer
    /// @param v2 Final byte of the signature of the second signer
    /// @param r2 First 32 bytes of the signature of the second signer
    /// @param s2 Second 32 bytes of the signature of the second signer
    function commit(
        bytes32 hashSecret,
        uint8 v1,
        bytes32 r1,
        bytes32 s1,
        uint8 v2,
        bytes32 r2,
        bytes32 s2
    ) external;

    /// @notice Reveals a secret if the commit exists and the signatures are valid
    /// @param secret Secret struct encapsulating the secret we want to reveal
    function reveal(Secret calldata secret) external;

    /// @dev Leverages solady EIP712 to get full hash of our secret, domain separator and EIP-191 version byte
    /// @param secret Secret struct encapsulating the secret we want to sign
    /// @return typedDataHash Full hash of our secret, domain separator and EIP-191 version byte
    function hashTypedData(
        Secret calldata secret
    ) external view returns (bytes32 typedDataHash);

    /// @notice Checks if a commit exists
    /// @param hashSecret Hash of the secret we want to check
    /// @return exists Boolean indicating if the commit exists
    function commitExists(
        bytes32 hashSecret
    ) external view returns (bool exists);
}
