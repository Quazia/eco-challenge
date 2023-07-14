// SPDX-License-Identifier: Unlicense
pragma solidity 0.8.19;
import {Secret, SECRET_TYPEHASH} from "src/types/structs/Secret.sol";
import {Commitment, Signature} from "src/types/structs/Commitment.sol";
import {EIP712} from "solady/utils/EIP712.sol";

contract SecretCommit is EIP712 {
    mapping(bytes32 => Commitment) public commitments;
    event Reveal(bytes indexed secret, address indexed revealer);

    function _domainNameAndVersion()
        internal
        pure
        override
        returns (string memory name, string memory version)
    {
        name = "SecretCommit";
        version = "1";
    }

    function hashStruct(
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

    function hashTypedData(
        Secret calldata secret
    ) public view virtual returns (bytes32 digest) {
        return _hashTypedData(hashStruct(secret));
    }

    function commitExists(bytes32 hashSecret) public view returns (bool) {
        return commitments[hashSecret].hashSecret == hashSecret;
    }

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

    function reveal(Secret calldata secret) external {
        bytes32 digest = hashTypedData(secret);
        require(commitExists(digest), "Commit does not exist");
        Commitment memory commitment = commitments[digest];
        Signature memory signatureOne = commitment.signatureOne;
        Signature memory signatureTwo = commitment.signatureTwo;
        require(
            ecrecover(digest, signatureOne.v, signatureOne.r, signatureOne.s) ==
                secret.signerOne &&
                ecrecover(
                    digest,
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
        delete commitments[digest];
    }
}
