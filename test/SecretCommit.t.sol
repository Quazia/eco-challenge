// SPDX-License-Identifier: Unlicense
pragma solidity 0.8.19;

import "forge-std/Test.sol";
import "forge-std/console.sol";

import {SecretCommit} from "src/SecretCommit.sol";

import {Secret} from "src/types/structs/Secret.sol";

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
        bytes32 hashSecret = secretCommit.hashTypedData(secretStruct);
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(akey, hashSecret);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(bkey, hashSecret);
        vm.prank(alice);
        secretCommit.commit(hashSecret, v1, r1, s1, v2, r2, s2);
        bool exists = secretCommit.commitExists(hashSecret);
        assertTrue(exists);
    }

    function testFuzz_Commit() public {
        assert(false);
    }

    function test_RevertIf_CommitExists() public {
        assert(false);
    }

    function test_RevertIf_InvalidSender() public {
        assert(false);
    }
}

contract Reveal is Test {
    SecretCommit secretCommit;
    address alice;
    address bob;
    uint256 akey;
    uint256 bkey;

    function setUp() public {
        (alice, akey) = makeAddrAndKey("alice");
        (bob, bkey) = makeAddrAndKey("bob");
        secretCommit = new SecretCommit();
        bytes memory secret = abi.encode("secret");
        Secret memory secretStruct = Secret(alice, bob, secret);
        bytes32 hashSecret = secretCommit.hashTypedData(secretStruct);
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(akey, hashSecret);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(bkey, hashSecret);
        vm.prank(alice);
        secretCommit.commit(hashSecret, v1, r1, s1, v2, r2, s2);
    }

    function test_Reveal() public {
        assert(false);
    }

    function testFuzz_Reveal() public {
        assert(false);
    }

    function test_RevertIf_CommitDoesNotExist() public {
        assert(false);
    }
}
