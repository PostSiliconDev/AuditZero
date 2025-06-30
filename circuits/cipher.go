package circuits

import (
	"fmt"

	poseidonbn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon2"
	"github.com/consensys/gnark/frontend"
	poseidon "github.com/consensys/gnark/std/permutation/poseidon2"
)

type StreamCipherGadget struct {
	Key [2]frontend.Variable
}

func (gadget *StreamCipherGadget) Encrypt(api frontend.API, ad []frontend.Variable, plaintext []frontend.Variable) (frontend.Variable, error) {
	params := poseidonbn254.GetDefaultParameters()
	perm, err := poseidon.NewPoseidon2FromParameters(api, 2, params.NbFullRounds, params.NbPartialRounds)
	if err != nil {
		return nil, fmt.Errorf("failed to create poseidon permutation: %w", err)
	}

	state := []frontend.Variable{
		0, 0,
	}

	perm.Permutation(state)

	state[0] = gadget.Key[0]
	perm.Permutation(state)

	state[0] = gadget.Key[1]
	perm.Permutation(state)

	for i := range ad {
		state[0] = api.Add(state[0], ad[i])
		perm.Permutation(state)
	}

	for i := range plaintext {
		perm.Permutation(state)

		state[0] = api.Add(state[0], plaintext[i])
		perm.Permutation(state)
	}

	return state[0], nil
}
