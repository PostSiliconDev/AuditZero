#!/bin/bash

CIRCOM_NAME=$1
INPUT_FILE=$2

cp testdata/${INPUT_FILE}.json target/circuits/${INPUT_FILE}.json || exit 1

cd target/circuits || exit 1

node ${CIRCOM_NAME}_js/generate_witness.js ${CIRCOM_NAME}_js/${CIRCOM_NAME}.wasm ${INPUT_FILE}.json witness.wtns || exit 1
echo "Witness generated"
time snarkjs groth16 prove ${CIRCOM_NAME}_0001.zkey witness.wtns proof.json public.json || exit 1
