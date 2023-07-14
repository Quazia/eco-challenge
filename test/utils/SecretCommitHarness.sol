// SPDX-License-Identifier: Unlicense
pragma solidity 0.8.19;

import {SecretCommit} from "src/SecretCommit.sol";
import {Secret, SECRET_TYPEHASH} from "src/types/structs/Secret.sol";

contract SecretCommitHarness is SecretCommit {
    function hashStruct(
        Secret calldata secret
    ) public pure returns (bytes32 structHash) {
        return super._hashStruct(secret);
    }

    /// @dev Naive implementation to run gas optimization tests against
    /// @param secret Secret struct encapsulating the secret we want to sign
    /// @return structHash Hash of the secret struct
    function hashStructNaive(
        Secret calldata secret
    ) public pure returns (bytes32 structHash) {
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

    function domainNameAndVersion()
        public
        pure
        returns (string memory name, string memory version)
    {
        return super._domainNameAndVersion();
    }
}
