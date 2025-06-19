package main

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	poseidonbn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon2"
)

func main() {
	params := poseidonbn254.GetDefaultParameters()

	hasher := poseidonbn254.NewPermutation(params.Width, params.NbFullRounds, params.NbPartialRounds)

	input := []fr.Element{
		fr.NewElement(0),
		fr.NewElement(0),
	}
	fmt.Println(input[0].Text(10), input[1].Text(10))

	hasher.Permutation(input)
	fmt.Println(input[0].Text(10), input[1].Text(10))

	hasher.Permutation(input)
	fmt.Println(input[0].Text(10), input[1].Text(10))

	hasher.Permutation(input)
	fmt.Println(input[0].Text(10), input[1].Text(10))
}
