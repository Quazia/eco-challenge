// SPDX-License-Identifier: Unlicense
pragma solidity 0.8.19;

import "forge-std/Test.sol";

import "src/SecretCommit.sol";

contract Commit is Test {
    SecretCommit secretCommit;

    function setUp() public {
        secretCommit = new SecretCommit();
    }
}

contract Reveal is Test {
    SecretCommit secretCommit;

    function setUp() public {
        secretCommit = new SecretCommit();
        // Perform Commit Logic in setup
    }
}
