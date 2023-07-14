// SPDX-License-Identifier: Unlicense
pragma solidity 0.8.19;
import "src/types/structs/Secret.sol";
import "solady/utils/EIP712.sol";

contract SecretCommit is EIP712 {
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
        Secret memory secret
    ) internal pure returns (bytes32 hash) {
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
        Secret memory secret
    ) external view virtual returns (bytes32 digest) {
        _hashTypedData(hashStruct(secret));
    }
}
