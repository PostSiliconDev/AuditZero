package main

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	gnarksha3 "github.com/consensys/gnark/std/hash/sha3"
	"github.com/consensys/gnark/std/math/uints"
)

func BuildHashInput(api frontend.API, input frontend.Variable) []uints.U8 {
	inputBits := api.ToBinary(input, 254)

	inputBytes := make([]uints.U8, 32)

	for i := 0; i < 32; i++ {
		byteVar := api.FromBinary(inputBits[i*8 : (i+1)*8]...)

		binaryField, _ := uints.New[uints.U32](api)
		inputBytes[i] = binaryField.ByteValueOf(byteVar)
	}

	return inputBytes
}

type TestCircuit struct {
	Input0 frontend.Variable `gnark:"input0"`
	Input1 frontend.Variable `gnark:"input1"`
}

func (circuit *TestCircuit) Define(api frontend.API) error {
	in1Bits := api.ToBinary(circuit.Input0, 256)
	in2Bits := api.ToBinary(circuit.Input1, 256)

	inputBits := append(in1Bits, in2Bits...)

	inputBytes := make([]uints.U8, 64)

	for i := 0; i < 64; i++ {
		byteVar := api.FromBinary(inputBits[i*8 : (i+1)*8]...)

		binaryField, _ := uints.New[uints.U32](api)
		inputBytes[i] = binaryField.ByteValueOf(byteVar)
	}

	sha3Hasher, _ := gnarksha3.New256(api)
	sha3Hasher.Write(inputBytes)

	sha3Bytes := sha3Hasher.Sum()

	for i := range sha3Bytes {
		api.Println(sha3Bytes[i])
	}

	return nil
}

func main() {
	circuit := TestCircuit{}

	assignment := TestCircuit{
		Input0: fr.NewElement(0),
		Input1: fr.NewElement(1),
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
