pragma circom 2.1.5;

include "poseidon.circom";

template ComputeCommitment() {
    signal input asset;
    signal input amount;
    signal input blinding;

    signal output commitment;

    component poseidon = Poseidon(3);
    poseidon.inputs[0] <== asset;
    poseidon.inputs[1] <== amount;
    poseidon.inputs[2] <== blinding;

    commitment <== poseidon.out;
}