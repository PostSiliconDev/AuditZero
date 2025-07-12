package main

import (
	"fmt"
	"hide-pay/builder"
	"hide-pay/circuits"
	"math/big"
	"os"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon2"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
)

func main() {
	receiverPublicKey, _, err := circuits.CreatePublicFromRand()
	if err != nil {
		panic(err)
	}

	auditPublicKey, _, err := circuits.CreatePublicFromRand()
	if err != nil {
		panic(err)
	}

	_, senderSecretKey, err := circuits.CreatePublicFromRand()
	if err != nil {
		panic(err)
	}

	blinding0, err := circuits.CreateSeedFromRand()
	if err != nil {
		panic(err)
	}

	blinding1, err := circuits.CreateSeedFromRand()
	if err != nil {
		panic(err)
	}

	blinding2, err := circuits.CreateSeedFromRand()
	if err != nil {
		panic(err)
	}

	blinding3, err := circuits.CreateSeedFromRand()
	if err != nil {
		panic(err)
	}

	blinding4, err := circuits.CreateSeedFromRand()
	if err != nil {
		panic(err)
	}

	blinding5, err := circuits.CreateSeedFromRand()
	if err != nil {
		panic(err)
	}

	blinding6, err := circuits.CreateSeedFromRand()
	if err != nil {
		panic(err)
	}

	blinding7, err := circuits.CreateSeedFromRand()
	if err != nil {
		panic(err)
	}

	EphemeralReceiverSecretKey1, err := circuits.CreateSeedFromRand()
	if err != nil {
		panic(err)
	}

	EphemeralReceiverSecretKey2, err := circuits.CreateSeedFromRand()
	if err != nil {
		panic(err)
	}

	EphemeralReceiverSecretKey3, err := circuits.CreateSeedFromRand()
	if err != nil {
		panic(err)
	}

	EphemeralReceiverSecretKey4, err := circuits.CreateSeedFromRand()
	if err != nil {
		panic(err)
	}

	EphemeralAuditSecretKey1, err := circuits.CreateSeedFromRand()
	if err != nil {
		panic(err)
	}

	EphemeralAuditSecretKey2, err := circuits.CreateSeedFromRand()
	if err != nil {
		panic(err)
	}

	EphemeralAuditSecretKey3, err := circuits.CreateSeedFromRand()
	if err != nil {
		panic(err)
	}

	EphemeralAuditSecretKey4, err := circuits.CreateSeedFromRand()
	if err != nil {
		panic(err)
	}

	nullifier := builder.Nullifier{
		Commitment: builder.Commitment{
			Asset:    fr.NewElement(1),
			Amount:   fr.NewElement(2),
			Blinding: circuits.BigIntToFr(blinding0),
		},
		SpentPrivateKey: circuits.BigIntToFr(senderSecretKey),
	}

	nullifier0 := nullifier
	nullifier1 := nullifier
	nullifier2 := nullifier
	nullifier3 := nullifier

	nullifier0.Blinding = circuits.BigIntToFr(blinding0)
	nullifier1.Blinding = circuits.BigIntToFr(blinding1)
	nullifier2.Blinding = circuits.BigIntToFr(blinding2)
	nullifier3.Blinding = circuits.BigIntToFr(blinding3)

	depth := 34

	merkleTree := builder.NewMerkleTree(depth, poseidon2.NewMerkleDamgardHasher())
	elems := []fr.Element{
		nullifier0.Commitment.Compute(),
		nullifier1.Commitment.Compute(),
		nullifier2.Commitment.Compute(),
		nullifier3.Commitment.Compute(),
	}
	merkleTree.Build(elems)

	merkleProof0 := merkleTree.GetProof(0)
	merkleProof1 := merkleTree.GetProof(1)
	merkleProof2 := merkleTree.GetProof(2)
	merkleProof3 := merkleTree.GetProof(3)

	utxo := &builder.UTXO{
		Nullifier: []builder.Nullifier{
			nullifier0,
			nullifier1,
			nullifier2,
			nullifier3,
		},
		MerkleProof: []builder.MerkleProof{
			merkleProof0,
			merkleProof1,
			merkleProof2,
			merkleProof3,
		},
		Commitment: []builder.Commitment{
			{
				Asset:    fr.NewElement(1),
				Amount:   fr.NewElement(2),
				Blinding: circuits.BigIntToFr(blinding4),
			},
			{
				Asset:    fr.NewElement(1),
				Amount:   fr.NewElement(2),
				Blinding: circuits.BigIntToFr(blinding5),
			},
			{
				Asset:    fr.NewElement(1),
				Amount:   fr.NewElement(2),
				Blinding: circuits.BigIntToFr(blinding6),
			},
			{
				Asset:    fr.NewElement(1),
				Amount:   fr.NewElement(2),
				Blinding: circuits.BigIntToFr(blinding7),
			},
		},
		EphemeralReceiverSecretKey: []big.Int{
			EphemeralReceiverSecretKey1,
			EphemeralReceiverSecretKey2,
			EphemeralReceiverSecretKey3,
			EphemeralReceiverSecretKey4,
		},
		EphemeralAuditSecretKey: []big.Int{
			EphemeralAuditSecretKey1,
			EphemeralAuditSecretKey2,
			EphemeralAuditSecretKey3,
			EphemeralAuditSecretKey4,
		},
		ReceiverPublicKey: receiverPublicKey.PointAffine,
		AuditPublicKey:    auditPublicKey.PointAffine,
	}

	result, err := utxo.BuildAndCheck()
	if err != nil {
		panic(err)
	}

	assignment, err := builder.NewUTXOCircuitWitness(utxo, result)
	if err != nil {
		panic("build assignment: " + err.Error())
	}

	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		panic("build witness: " + err.Error())
	}

	publicWitness, err := witness.Public()
	if err != nil {
		panic("build public witness: " + err.Error())
	}

	fmt.Println("start read cs")
	csbuf, err := os.Open("./cs.dat")
	if err != nil {
		panic("open cs: " + err.Error())
	}
	cs := groth16.NewCS(ecc.BN254)
	cs.ReadFrom(csbuf)

	fmt.Println("start read pk")
	pkBuf, err := os.Open("./pk.dat")
	if err != nil {
		panic("open pk: " + err.Error())
	}
	pk := groth16.NewProvingKey(ecc.BN254)
	pk.ReadFrom(pkBuf)

	fmt.Println("start read vk")
	vkBuf, err := os.Open("./vk.dat")
	if err != nil {
		panic("open vk: " + err.Error())
	}
	vk := groth16.NewVerifyingKey(ecc.BN254)
	vk.ReadFrom(vkBuf)

	fmt.Println("start prove")
	t0 := time.Now()
	proof, err := groth16.Prove(cs, pk, witness)
	if err != nil {
		panic("prove: " + err.Error())
	}
	t1 := time.Now()
	fmt.Println("prove time", t1.Sub(t0))

	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		panic("verify: " + err.Error())
	}
}
