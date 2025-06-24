package main

import (
	"fmt"
	circuits "hide-pay/circuits/gnark"
	"math/big"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
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

	utxo := &circuits.UTXO{
		Nullifier: []circuits.Nullifier{
			{
				Commitment: circuits.Commitment{
					Asset:    fr.NewElement(1),
					Amount:   fr.NewElement(2),
					Blinding: circuits.BigIntToFr(blinding0),
				},
				PrivateKey: circuits.BigIntToFr(senderSecretKey),
			},
			{
				Commitment: circuits.Commitment{
					Asset:    fr.NewElement(1),
					Amount:   fr.NewElement(2),
					Blinding: circuits.BigIntToFr(blinding1),
				},
				PrivateKey: circuits.BigIntToFr(senderSecretKey),
			},
			{
				Commitment: circuits.Commitment{
					Asset:    fr.NewElement(1),
					Amount:   fr.NewElement(2),
					Blinding: circuits.BigIntToFr(blinding2),
				},
				PrivateKey: circuits.BigIntToFr(senderSecretKey),
			},
			{
				Commitment: circuits.Commitment{
					Asset:    fr.NewElement(1),
					Amount:   fr.NewElement(2),
					Blinding: circuits.BigIntToFr(blinding3),
				},
				PrivateKey: circuits.BigIntToFr(senderSecretKey),
			},
		},
		Commitment: []circuits.Commitment{
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

	assignment := circuits.NewUTXOCircuitWitness(utxo, result)

	witness, _ := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	publicWitness, _ := witness.Public()

	utxoCircuit := circuits.NewUTXOCircuit(len(result.AllAsset), len(utxo.Nullifier), len(utxo.Commitment))

	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, utxoCircuit)
	if err != nil {
		panic(err)
	}

	pk, vk, err := groth16.Setup(cs)
	if err != nil {
		panic(err)
	}

	start := time.Now()

	proof, err := groth16.Prove(cs, pk, witness)
	if err != nil {
		panic(err)
	}

	elapsed := time.Since(start)
	fmt.Println("Prove time:", elapsed)

	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		panic(err)
	}
}
