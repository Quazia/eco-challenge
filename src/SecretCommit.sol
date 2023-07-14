// SPDX-License-Identifier: Unlicense
pragma solidity 0.8.19;
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
}
