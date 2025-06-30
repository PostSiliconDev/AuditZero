// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "./Commitment.sol";
import "./Nullifier.sol";

contract HidePay is CommitmentStorage, NullifierStorage {
    event CommitmentAdded(
        uint256 indexed index,
        bytes32 indexed commitment,
        bytes32[] ownerMemo,
        bytes32[] auditMemo
    );

    struct Transaction {
        bytes32[] nullifier;
        bytes32[] commitment;
        bytes32[] ownerMemo;
        bytes32[] auditMemo;
    }

    error NullifierAlreadyUsed(bytes32 nullifier);
    error CommitmentAlreadyUsed(bytes32 commitment);

    function submitBlock(
        MerkleUpdater calldata merkleUpdater,
        bytes calldata merkleUpdaterProof,
        Transaction[] calldata transactions,
        bytes[] calldata /* transactionsProofs */
    ) public {
        for (uint256 i = 0; i < transactions.length; i++) {
            for (uint256 j = 0; j < transactions[i].nullifier.length; j++) {
                if (nullifiers[transactions[i].nullifier[j]]) {
                    revert NullifierAlreadyUsed(transactions[i].nullifier[j]);
                }
            }

            for (uint256 j = 0; j < transactions[i].commitment.length; j++) {
                if (usedCommitments[transactions[i].commitment[j]]) {
                    revert CommitmentAlreadyUsed(transactions[i].commitment[j]);
                }
            }
        }

        updateMerkleTree(merkleUpdater, merkleUpdaterProof);

        for (uint256 i = 0; i < transactions.length; i++) {
            // TODO: verify transactionsProofs

            for (uint256 j = 0; j < transactions[i].nullifier.length; j++) {
                addNullifier(transactions[i].nullifier[j]);
            }

            for (uint256 j = 0; j < transactions[i].commitment.length; j++) {
                addCommitment(transactions[i].commitment[j]);

                // TODO: split ownerMemo and auditMemo into multiple events
                emit CommitmentAdded(
                    lastCommitmentIndex,
                    transactions[i].commitment[j],
                    transactions[i].ownerMemo,
                    transactions[i].auditMemo
                );
            }
        }
    }
}
