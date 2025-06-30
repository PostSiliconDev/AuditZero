// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

contract NullifierStorage {
    mapping(bytes32 => bool) public nullifiers;

    function addNullifier(bytes32 nullifier) internal {
        nullifiers[nullifier] = true;
    }
}
