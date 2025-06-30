// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

contract CommitmentStorage {
    mapping(uint256 => bytes32) public commitments;
    mapping(bytes32 => bool) public usedCommitments;

    bytes32 public commitmentRoot;

    uint256 public lastCommitmentIndex;

    function addCommitment(bytes32 commitment) internal {
        commitments[lastCommitmentIndex] = commitment;
        lastCommitmentIndex++;
    }

    struct MerkleUpdater {
        bytes32 oldRoot;
        bytes32 newRoot;
        bytes32[] newCommitments;
    }

    error OldMerkleRootNotMatch(bytes32 oldRoot);

    function updateMerkleTree(
        MerkleUpdater calldata merkleUpdater,
        bytes calldata /* proof */
    ) public {
        if (merkleUpdater.oldRoot != commitmentRoot) {
            revert OldMerkleRootNotMatch(merkleUpdater.oldRoot);
        }

        // TODO: verify proof

        commitmentRoot = merkleUpdater.newRoot;
        for (uint256 i = 0; i < merkleUpdater.newCommitments.length; i++) {
            addCommitment(merkleUpdater.newCommitments[i]);
            usedCommitments[merkleUpdater.newCommitments[i]] = true;
        }
    }
}
