// SPDX-License-Identifier: Unlicense
pragma solidity 0.8.19;

import {ISecretCommit} from "src/types/interfaces/ISecretCommit.sol";
import {Secret, SECRET_TYPEHASH} from "src/types/structs/Secret.sol";
import {Commitment, Signature} from "src/types/structs/Commitment.sol";
import {EIP712} from "solady/utils/EIP712.sol";
error InvalidSignature();
error CommitAlreadyExists();
error CommitDoesNotExist();
error InvalidRevealer();

/// @notice This contract allows exactly two parties to commit to and reveal a secret
/// @author Arthur Lunn
contract SecretCommit is EIP712, ISecretCommit {
    mapping(bytes32 => Commitment) public commitments;

    ///@inheritdoc ISecretCommit
    function commit(
        bytes32 hashSecret,
        uint8 v1,
        bytes32 r1,
        bytes32 s1,
        uint8 v2,
        bytes32 r2,
        bytes32 s2
    ) external {
        if (
            ecrecover(hashSecret, v1, r1, s1) != msg.sender &&
            ecrecover(hashSecret, v2, r2, s2) != msg.sender
        ) revert InvalidSignature();
        if (commitExists(hashSecret)) revert CommitAlreadyExists();
        commitments[hashSecret] = Commitment(
            Signature(v1, r1, s1),
            Signature(v2, r2, s2),
            hashSecret
        );
    }

    ///@inheritdoc ISecretCommit
    function reveal(Secret calldata secret) external {
        bytes32 typedDataHash = hashTypedData(secret);
        if (!commitExists(typedDataHash)) revert CommitDoesNotExist();
        Commitment memory commitment = commitments[typedDataHash];
        Signature memory signatureOne = commitment.signatureOne;
        Signature memory signatureTwo = commitment.signatureTwo;
        if (
            ecrecover(
                typedDataHash,
                signatureOne.v,
                signatureOne.r,
                signatureOne.s
            ) !=
            secret.signerOne ||
            ecrecover(
                typedDataHash,
                signatureTwo.v,
                signatureTwo.r,
                signatureTwo.s
            ) !=
            secret.signerTwo
        ) revert InvalidSignature();
        if (secret.signerOne != msg.sender && secret.signerTwo != msg.sender)
            revert InvalidRevealer();
        emit Reveal(secret.payload, msg.sender);
        delete commitments[typedDataHash];
    }

    ///@inheritdoc ISecretCommit
    function hashTypedData(
        Secret calldata secret
    ) public view returns (bytes32 typedDataHash) {
        return _hashTypedData(_hashStruct(secret));
    }

    ///@inheritdoc ISecretCommit
    function commitExists(
        bytes32 hashSecret
    ) public view returns (bool exists) {
        return commitments[hashSecret].hashSecret == hashSecret;
    }

    /// @dev Overriden to enable EIP712
    /// @return name Name of this contract for use in domain separator
    /// @return version Version of this contract for use in domain separator
    function _domainNameAndVersion()
        internal
        pure
        override
        returns (string memory name, string memory version)
    {
        name = "SecretCommit";
        version = "1";
    }

    /// @dev Gives us the hash of our main secret for use in EIP712 signing
    /// @param secret Secret struct encapsulating the secret we want to sign
    /// @return structHash Hash of the secret struct
    function _hashStruct(
        Secret calldata secret
    ) internal pure returns (bytes32 structHash) {
        bytes32 payloadHash = keccak256(secret.payload);
        assembly {
            let m := mload(0x40) // Load the free memory pointer.
            mstore(m, SECRET_TYPEHASH)
            mstore(add(m, 0x20), calldataload(0x24)) // Get the first signer from calldata
            mstore(add(m, 0x40), calldataload(0x44)) // Get the second signer from calldata
            mstore(add(m, 0x60), payloadHash)
            structHash := keccak256(m, 0x80)
        }
    }
}
