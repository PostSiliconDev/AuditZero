package main

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	poseidonbn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon2"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/hash"
	"github.com/consensys/gnark/std/permutation/poseidon2"
)

type TestCircuit struct {
	Input0 frontend.Variable `gnark:"input0"`
	Input1 frontend.Variable `gnark:"input1"`
}

func (circuit *TestCircuit) Define(api frontend.API) error {
	params := poseidonbn254.GetDefaultParameters()
	perm, err := poseidon2.NewPoseidon2FromParameters(api, params.Width, params.NbFullRounds, params.NbPartialRounds)

	if err != nil {
		return err
	}

	hasher := hash.NewMerkleDamgardHasher(api, perm, 0)

	hasher.Write(circuit.Input0)
	hasher.Write(circuit.Input1)

	hash := hasher.Sum()

	api.Println(hash)

	return nil
}

func main() {
	Input0 := fr.NewElement(0)
	Input1 := fr.NewElement(1)

	hasher := poseidonbn254.NewMerkleDamgardHasher()

	hasher.Write(Input0.Marshal())
	hasher.Write(Input1.Marshal())

	hashBytes := hasher.Sum(nil)
	hash := fr.NewElement(0)
	hash.SetBytes(hashBytes)

	fmt.Println(hash.Text(10))

	circuit := TestCircuit{}

	assignment := TestCircuit{
		Input0: Input0,
		Input1: Input1,
	}

	witness, _ := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	publicWitness, _ := witness.Public()

	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		panic(err)
	}

	pk, vk, err := groth16.Setup(cs)
	if err != nil {
		panic(err)
	}

	proof, err := groth16.Prove(cs, pk, witness)
	if err != nil {
		panic(err)
	}

	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		panic(err)
	}
}
