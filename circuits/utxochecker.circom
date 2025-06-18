pragma circom 2.1.5;

include "comparators.circom";
include "commitment.circom";
include "nullifier.circom";
include "ownermemo.circom";

template UTXOChecker(nAssets, nIns, nOuts) {
    // signal input all_assets[nAssets];

    signal input inAssets[nIns];
    signal input inAmounts[nIns];
    signal input inBlindings[nIns];
    signal input inSecretKeys[nIns];

    signal input outAssets[nOuts];
    signal input outAmounts[nOuts];
    signal input outBlindings[nOuts];
    signal input encryptNonce[nOuts];

    signal input receiverPublicKey[2];
    signal input auditPublicKey[2];

    signal output nullifiers[nIns];
    signal output commitments[nOuts];
    signal output ownerMemosHash[nOuts];

    // Sum up inputs using intermediate signals
    // for (var i = 0; i < nAssets; i++) {}

    // component ise_out[nAssets * nOuts];

    // for (var i = 0; i < nAssets * nOuts; i++) {
    //     ise_out[i] = IsEqual();
    // }

    // /// Sum up outputs
    // for (var i = 0; i < nOuts; i++) {
    //     for (var j = 0; j < nAssets; j++) {
    //         component ise = IsEqual();
    //         ise.in[0] <== out_asset[i];
    //         ise.in[1] <== all_assets[j];
    //         out_sums[j] <== out_sums[j] + out_amount[i] * ise.out;  
    //     }
    // }

    // /// Check if the sum of inputs is equal to the sum of outputs
    // for (var i = 0; i < nAssets; i++) {
    //     in_sums[i] === out_sums[i];
    // }

    /// Compute commitments and nullifiers
    component input_compute_commitments[nIns];
    component input_compute_nullifiers[nIns];
    component input_empty[nIns];

    for (var i = 0; i < nIns; i++) {
        input_compute_commitments[i] = ComputeCommitment();
        input_compute_nullifiers[i] = ComputeNullifier();
        input_empty[i] = IsZero();

        input_compute_commitments[i].asset <== inAssets[i];
        input_compute_commitments[i].amount <== inAmounts[i];
        input_compute_commitments[i].blinding <== inBlindings[i];

        input_compute_nullifiers[i].commitment <== input_compute_commitments[i].commitment;
        input_compute_nullifiers[i].secret_key <== inSecretKeys[i];

        input_empty[i].in <== inAssets[i];

        nullifiers[i] <== input_compute_nullifiers[i].nullifier * (1 - input_empty[i].out);
    }

    component output_compute_commitments[nOuts];
    component output_empty[nOuts];
    component output_owner_memos[nOuts];

    for (var i = 0; i < nOuts; i++) {
        output_compute_commitments[i] = ComputeCommitment();
        output_compute_commitments[i].asset <== outAssets[i];
        output_compute_commitments[i].amount <== outAmounts[i];
        output_compute_commitments[i].blinding <== outBlindings[i];

        output_empty[i] = IsZero();
        output_empty[i].in <== outAssets[i];

        commitments[i] <== output_compute_commitments[i].commitment * (1 - output_empty[i].out);

        output_owner_memos[i] = OwnerMemo();
        output_owner_memos[i].asset <== outAssets[i];
        output_owner_memos[i].amount <== outAmounts[i];
        output_owner_memos[i].blinding <== outBlindings[i];
        output_owner_memos[i].nonceKey <== encryptNonce[i];
        output_owner_memos[i].publicKey <== receiverPublicKey;
        output_owner_memos[i].auditPublicKey <== auditPublicKey;

        ownerMemosHash[i] <== output_owner_memos[i].encryptedHash * (1 - output_empty[i].out);
    }
}

component main { public [auditPublicKey] } = UTXOChecker(6, 6, 2);