// SPDX-License-Identifier: Unlicense
pragma solidity 0.8.19;

import {Secret, SECRET_TYPEHASH} from "src/types/structs/Secret.sol";
import {Commitment, Signature} from "src/types/structs/Commitment.sol";
import {EIP712} from "solady/utils/EIP712.sol";

/// @notice This contract allows exactly two parties to commit to and reveal a secret
/// @author Arthur Lunn
contract SecretCommit is EIP712 {
    event Reveal(bytes indexed secret, address indexed revealer);
    mapping(bytes32 => Commitment) public commitments;

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
    ) external {
        require(
            ecrecover(hashSecret, v1, r1, s1) == msg.sender ||
                ecrecover(hashSecret, v2, r2, s2) == msg.sender,
            "Invalid signature"
        );
        require(!commitExists(hashSecret), "Commit already exists");
        commitments[hashSecret] = Commitment(
            Signature(v1, r1, s1),
            Signature(v2, r2, s2),
            hashSecret
        );
    }

    /// @notice Reveals a secret if the commit exists and the signatures are valid
    /// @param secret Secret struct encapsulating the secret we want to reveal
    function reveal(Secret calldata secret) external {
        bytes32 typedDataHash = hashTypedData(secret);
        require(commitExists(typedDataHash), "Commit does not exist");
        Commitment memory commitment = commitments[typedDataHash];
        Signature memory signatureOne = commitment.signatureOne;
        Signature memory signatureTwo = commitment.signatureTwo;
        require(
            ecrecover(
                typedDataHash,
                signatureOne.v,
                signatureOne.r,
                signatureOne.s
            ) ==
                secret.signerOne &&
                ecrecover(
                    typedDataHash,
                    signatureTwo.v,
                    signatureTwo.r,
                    signatureTwo.s
                ) ==
                secret.signerTwo,
            "Invalid signature"
        );
        require(
            secret.signerOne == msg.sender || secret.signerTwo == msg.sender,
            "Invalid revealer"
        );
        emit Reveal(secret.payload, msg.sender);
        delete commitments[typedDataHash];
    }

    /// @dev Leverages solady EIP712 to get full hash of our secret, domain separator and EIP-191 version byte
    /// @param secret Secret struct encapsulating the secret we want to sign
    /// @return typedDataHash Full hash of our secret, domain separator and EIP-191 version byte
    function hashTypedData(
        Secret calldata secret
    ) public view virtual returns (bytes32 typedDataHash) {
        return _hashTypedData(hashStruct(secret));
    }

    /// @notice Checks if a commit exists
    /// @param hashSecret Hash of the secret we want to check
    /// @return exists Boolean indicating if the commit exists
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
        return
            keccak256(
                abi.encode(
                    SECRET_TYPEHASH,
                    secret.signerOne,
                    secret.signerTwo,
                    keccak256(secret.payload)
                )
            );
    }
}
