package utils

import (
	poseidonbn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon2"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash"
	"github.com/consensys/gnark/std/permutation/poseidon2"
)

func NewPoseidonHasher(api frontend.API) (hash.FieldHasher, error) {
	params := poseidonbn254.GetDefaultParameters()
	perm, err := poseidon2.NewPoseidon2FromParameters(api, params.Width, params.NbFullRounds, params.NbPartialRounds)
	if err != nil {
		return nil, err
	}

	return hash.NewMerkleDamgardHasher(api, perm, 0), nil
}
