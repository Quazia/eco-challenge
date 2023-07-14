// SPDX-License-Identifier: Unlicense
pragma solidity 0.8.19;
//keccak256("Secret(address signerOne,address signerTwo,bytes secret)");
bytes32 constant SECRET_TYPEHASH = 0xc0a8491f98c899455e45c1bd6ccfdaee97e608c1fa0657d0b3419e1a9eb81030;

struct Secret {
    address signerOne;
    address signerTwo;
    bytes payload;
}
