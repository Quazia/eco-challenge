// SPDX-License-Identifier: Unlicense
pragma solidity 0.8.19;

import "forge-std/Test.sol";

import "src/SecretCommit.sol";

import "src/types/structs/Secret.sol";

contract Commit is Test {
    SecretCommit secretCommit;
    address alice;
    address bob;
    uint256 akey;
    uint256 bkey;

    function setUp() public {
        (alice, akey) = makeAddrAndKey("alice");
        (bob, bkey) = makeAddrAndKey("bob");
        secretCommit = new SecretCommit();
    }

    function test_Commit() public {
        bytes memory secret = abi.encode("secret");
        Secret memory secretStruct = Secret(alice, bob, secret);
        bool exists = false;
        bytes32 hashSecret = secretCommit.hashTypedData(secretStruct);
        // (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(akey, hashSecret);
        // (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(bkey, hashSecret);
        // secretCommit.commit(hashSecret, v1, r1, s1, v2, r2, s2);
        // bool exists = secretCommit.commitExists(hashSecret);
        assertTrue(exists);
    }
}

contract Reveal is Test {
    SecretCommit secretCommit;

    function setUp() public {
        secretCommit = new SecretCommit();
        // Perform Commit Logic in setup
    }
}
