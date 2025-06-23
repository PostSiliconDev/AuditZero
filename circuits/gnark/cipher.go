package circuits

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	poseidonbn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon2"
	"github.com/consensys/gnark/frontend"
	poseidon "github.com/consensys/gnark/std/permutation/poseidon2"
)

type StreamCipherGadget struct {
	Key [2]frontend.Variable
}

func (gadget *StreamCipherGadget) Encrypt(api frontend.API, ad []frontend.Variable, plaintext []frontend.Variable) (frontend.Variable, error) {
	api.Println("ad", ad)
	api.Println("plaintext", plaintext)

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

	for i := 0; i < len(ad); i++ {
		state[0] = api.Add(state[0], ad[i])
		perm.Permutation(state)
	}

	for i := 0; i < len(plaintext); i++ {
		perm.Permutation(state)

		state[0] = api.Add(state[0], plaintext[i])
		perm.Permutation(state)
	}

	return state[0], nil
}

type StreamCipher struct {
	Key [2]fr.Element
}

func (cipher *StreamCipher) ToGadget() *StreamCipherGadget {
	return &StreamCipherGadget{
		Key: [2]frontend.Variable{cipher.Key[0], cipher.Key[1]},
	}
}

func (cipher *StreamCipher) Encrypt(
	ad []fr.Element,
	plaintext []fr.Element,
) ([]fr.Element, error) {
	params := poseidonbn254.GetDefaultParameters()
	hasher := poseidonbn254.NewPermutation(2, params.NbFullRounds, params.NbPartialRounds)

	state := []fr.Element{
		fr.NewElement(0),
		fr.NewElement(0),
	}
	hasher.Permutation(state)

	state[0] = cipher.Key[0]
	hasher.Permutation(state)

	state[0] = cipher.Key[1]
	hasher.Permutation(state)

	for i := 0; i < len(ad); i++ {
		state[0].Add(&state[0], &ad[i])
		hasher.Permutation(state)
	}

	ciphertext := make([]fr.Element, len(plaintext)+1)

	for i := 0; i < len(plaintext); i++ {
		ciphertext[i].Add(&state[0], &plaintext[i])
		hasher.Permutation(state)

		state[0].Add(&state[0], &plaintext[i])
		hasher.Permutation(state)
	}

	// HMAC
	ciphertext[len(ciphertext)-1] = state[0]

	return ciphertext, nil
}

func (cipher *StreamCipher) Decrypt(
	ad []fr.Element,
	ciphertext []fr.Element,
) ([]fr.Element, error) {
	params := poseidonbn254.GetDefaultParameters()
	hasher := poseidonbn254.NewPermutation(2, params.NbFullRounds, params.NbPartialRounds)

	if len(ciphertext) == 0 {
		return nil, fmt.Errorf("ciphertext must have at least one element")
	}

	state := []fr.Element{
		fr.NewElement(0),
		fr.NewElement(0),
	}
	hasher.Permutation(state)

	state[0] = cipher.Key[0]
	hasher.Permutation(state)

	state[0] = cipher.Key[1]
	hasher.Permutation(state)

	for i := 0; i < len(ad); i++ {
		state[0].Add(&state[0], &ad[i])
		hasher.Permutation(state)
	}

	plaintext := make([]fr.Element, len(ciphertext)-1)

	for i := 0; i < len(ciphertext)-1; i++ {
		plaintext[i].Sub(&ciphertext[i], &state[0])
		hasher.Permutation(state)

		state[0].Add(&state[0], &plaintext[i])
		hasher.Permutation(state)
	}

	// HMAC
	if state[0] != ciphertext[len(ciphertext)-1] {
		return nil, fmt.Errorf("HMAC verification failed")
	}

	return plaintext, nil
}
