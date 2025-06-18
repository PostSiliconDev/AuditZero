pragma circom 2.1.5;

include "poseidon.circom";

template ComputeNullifier() {
    signal input commitment;
    signal input secret_key;

    signal output nullifier;

    component poseidon = Poseidon(3);
    poseidon.inputs[0] <== 1;
    poseidon.inputs[1] <== commitment;
    poseidon.inputs[2] <== secret_key;

    nullifier <== poseidon.out;
}