// SPDX-License-Identifier: Unlicense
pragma solidity 0.8.19;

import "forge-std/Test.sol";
import "forge-std/console.sol";

import {SecretCommit} from "src/SecretCommit.sol";
import {SecretCommitHarness} from "test/utils/SecretCommitHarness.sol";
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

    function testFuzz_Commit(bytes memory secret) public {
        Secret memory secretStruct = Secret(alice, bob, secret);
        bytes32 hashSecret = secretCommit.hashTypedData(secretStruct);
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(akey, hashSecret);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(bkey, hashSecret);
        vm.prank(alice);
        secretCommit.commit(hashSecret, v1, r1, s1, v2, r2, s2);
        bool exists = secretCommit.commitExists(hashSecret);
        assertTrue(exists);
    }

    function test_RevertIf_CommitExists() public {
        bytes memory secret = abi.encode("secret");
        Secret memory secretStruct = Secret(alice, bob, secret);
        bytes32 hashSecret = secretCommit.hashTypedData(secretStruct);
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(akey, hashSecret);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(bkey, hashSecret);
        vm.startPrank(alice);
        secretCommit.commit(hashSecret, v1, r1, s1, v2, r2, s2);
        bool exists = secretCommit.commitExists(hashSecret);
        assertTrue(exists);
        vm.expectRevert("Commit already exists");
        secretCommit.commit(hashSecret, v1, r1, s1, v2, r2, s2);
        // Not explicitly needed, but for clarity
        vm.stopPrank();
    }

    function test_RevertIf_InvalidSender() public {
        bytes memory secret = abi.encode("secret");
        Secret memory secretStruct = Secret(alice, bob, secret);
        bytes32 hashSecret = secretCommit.hashTypedData(secretStruct);
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(akey, hashSecret);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(bkey, hashSecret);
        vm.prank(alice);
        secretCommit.commit(hashSecret, v1, r1, s1, v2, r2, s2);
        bool exists = secretCommit.commitExists(hashSecret);
        assertTrue(exists);
        vm.expectRevert("Invalid signature");
        secretCommit.commit(hashSecret, v1, r1, s1, v2, r2, s2);
    }
}

contract Reveal is Test {
    SecretCommit secretCommit;
    address alice;
    address bob;
    uint256 akey;
    uint256 bkey;
    Secret secretStruct;
    bytes32 hashSecret;
    bytes secret;
    event Reveal(bytes indexed secret, address indexed revealer);

    function setUp() public {
        (alice, akey) = makeAddrAndKey("alice");
        (bob, bkey) = makeAddrAndKey("bob");
        secretCommit = new SecretCommit();
        secret = abi.encode("secret");
        secretStruct = Secret(alice, bob, secret);
        hashSecret = secretCommit.hashTypedData(secretStruct);
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(akey, hashSecret);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(bkey, hashSecret);
        vm.prank(alice);
        secretCommit.commit(hashSecret, v1, r1, s1, v2, r2, s2);
    }

    function test_Reveal() public {
        bool exists = secretCommit.commitExists(hashSecret);
        assertTrue(exists);
        vm.prank(alice);
        vm.expectEmit();
        emit Reveal(secret, alice);
        secretCommit.reveal(secretStruct);
        exists = secretCommit.commitExists(hashSecret);
        assertFalse(exists);
    }

    function test_RevertIf_CommitDoesNotExist() public {
        bytes memory differentSecret = abi.encode("differentSecret");
        Secret memory differentSecretStruct = Secret(
            alice,
            bob,
            differentSecret
        );
        vm.prank(alice);
        vm.expectRevert("Commit does not exist");
        secretCommit.reveal(differentSecretStruct);
    }

    function testFuzz_RevertIf_CommitDoesNotExist(
        string calldata secretString
    ) public {
        vm.assume(
            keccak256(abi.encodePacked(secretString)) !=
                keccak256(abi.encodePacked("secret"))
        );
        bytes memory differentSecret = abi.encode(secretString);
        Secret memory differentSecretStruct = Secret(
            alice,
            bob,
            differentSecret
        );
        vm.prank(alice);
        vm.expectRevert("Commit does not exist");
        secretCommit.reveal(differentSecretStruct);
    }

    function test_RevertIf_InvalidSender() public {
        vm.expectRevert("Invalid revealer");
        secretCommit.reveal(secretStruct);
    }

    function test_RevertIf_InvalidCounterparty() public {
        // This test is a bit of an edge case,
        // and realistically it might not actually be worth guarding against
        // but we want to test a mis-match between listed signers and actual signers.
        // If this edge case isn't important to guard against it's possible to slim
        // the implementation down a bit.
        address craig;
        uint256 ckey;
        (craig, ckey) = makeAddrAndKey("craig");
        Secret memory differentSecretStruct = Secret(alice, craig, secret);
        bytes32 differentHashSecret = secretCommit.hashTypedData(
            differentSecretStruct
        );
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(akey, differentHashSecret);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(bkey, differentHashSecret);
        vm.prank(alice);
        secretCommit.commit(differentHashSecret, v1, r1, s1, v1, r1, s1);
        vm.prank(alice);
        vm.expectRevert("Invalid signature");
        secretCommit.reveal(differentSecretStruct);
    }
}

contract HashStruct is Test {
    SecretCommitHarness secretCommitHarness;
    address alice;
    address bob;
    Secret secretStruct;
    bytes secret;

    function setUp() public {
        alice = makeAddr("alice");
        bob = makeAddr("bob");
        secret = abi.encode("secret");
        secretStruct = Secret(alice, bob, secret);
        secretCommitHarness = new SecretCommitHarness();
    }

    function test_HashStruct() public {
        assertEq(
            secretCommitHarness.hashStruct(secretStruct),
            secretCommitHarness.hashStructNaive(secretStruct)
        );
    }
}
