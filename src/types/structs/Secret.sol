// SPDX-License-Identifier: Unlicense
pragma solidity 0.8.19;

bytes32 constant SECRET_TYPEHASH = keccak256(
    "Secret(address signerOne,address signerTwo,bytes secret)"
);

struct Secret {
    address signerOne;
    address signerTwo;
    bytes secret;
}
