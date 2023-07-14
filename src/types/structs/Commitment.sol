// SPDX-License-Identifier: Unlicense
pragma solidity 0.8.19;
import "src/types/structs/Signature.sol";

struct Commitment {
    Signature signatureOne;
    Signature signatureTwo;
    bytes32 hashSecret;
}
