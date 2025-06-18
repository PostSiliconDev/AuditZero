pragma circom 2.1.2;

include "elgamal.circom";
include "poseidon.circom";

template OwnerMemo() {
    signal input asset;
    signal input amount;
    signal input blinding;

    signal input nonceKey;
    signal input publicKey[2];
    signal input auditPublicKey[2];

    signal output encryptedHash;

    component ownerMemo = OwnerMemoOnce();

    ownerMemo.asset <== asset;
    ownerMemo.amount <== amount;
    ownerMemo.blinding <== blinding;
    ownerMemo.nonceKey <== nonceKey;
    ownerMemo.publicKey <== publicKey;

    component auditMemo = OwnerMemoOnce();
    auditMemo.asset <== asset;
    auditMemo.amount <== amount;
    auditMemo.blinding <== blinding;
    auditMemo.nonceKey <== nonceKey;
    auditMemo.publicKey <== auditPublicKey;

    component poseidon = Poseidon(2);
    poseidon.inputs[0] <== ownerMemo.encryptedHash;
    poseidon.inputs[1] <== auditMemo.encryptedHash;

    poseidon.out ==> encryptedHash;
}

template OwnerMemoOnce() {
    signal input asset;
    signal input amount;
    signal input blinding;

    signal input nonceKey;
    signal input publicKey[2];

    signal output encryptedHash;

    component encryptAsset = EncryptPlainNumber();
    component encryptAmount = EncryptPlainNumber();
    component encryptBlinding = EncryptPlainNumber();

    encryptAsset.plaintext <== asset;
    encryptAmount.plaintext <== amount;
    encryptBlinding.plaintext <== blinding;

    encryptAsset.nonceKey <== nonceKey;
    encryptAsset.publicKey <== publicKey;

    encryptAmount.nonceKey <== nonceKey;
    encryptAmount.publicKey <== publicKey;

    encryptBlinding.nonceKey <== nonceKey;
    encryptBlinding.publicKey <== publicKey;

    component poseidon = Poseidon(12);

    poseidon.inputs[0] <== encryptAsset.encrypted[0];
    poseidon.inputs[1] <== encryptAsset.encrypted[1];
    poseidon.inputs[2] <== encryptAsset.encrypted[2];
    poseidon.inputs[3] <== encryptAsset.encrypted[3];
    poseidon.inputs[4] <== encryptAmount.encrypted[0];
    poseidon.inputs[5] <== encryptAmount.encrypted[1];
    poseidon.inputs[6] <== encryptAmount.encrypted[2];
    poseidon.inputs[7] <== encryptAmount.encrypted[3];
    poseidon.inputs[8] <== encryptBlinding.encrypted[0];
    poseidon.inputs[9] <== encryptBlinding.encrypted[1];
    poseidon.inputs[10] <== encryptBlinding.encrypted[2];
    poseidon.inputs[11] <== encryptBlinding.encrypted[3];

    poseidon.out ==> encryptedHash;
}

template EncryptPlainNumber() {
    signal input plaintext;
    signal input nonceKey;
    signal input publicKey[2];
    signal output encrypted[4];

    component encode = Encode();
    component encrypt = Encrypt();

    encode.plaintext <== plaintext;

    encode.out ==> encrypt.message;

    encrypt.nonceKey <== nonceKey;
    encrypt.publicKey <== publicKey;

    encrypted[0] <== encrypt.ephemeralKey[0];
    encrypted[1] <== encrypt.ephemeralKey[1];
    encrypted[2] <== encrypt.encryptedMessage[0];
    encrypted[3] <== encrypt.encryptedMessage[1];
}