package circuits

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	poseidonbn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon2"
	"github.com/consensys/gnark/frontend"
	poseidon "github.com/consensys/gnark/std/permutation/poseidon2"
)

type StreamCipherGadget struct {
	api frontend.API
}

func NewStreamCipherGadget(api frontend.API) *StreamCipherGadget {
	return &StreamCipherGadget{
		api: api,
	}
}

func (gadget *StreamCipherGadget) Encrypt(key [2]frontend.Variable, plaintext []frontend.Variable) ([]frontend.Variable, error) {
	params := poseidonbn254.GetDefaultParameters()
	perm, err := poseidon.NewPoseidon2FromParameters(gadget.api, params.Width, params.NbFullRounds, params.NbPartialRounds)
	if err != nil {
		return nil, fmt.Errorf("failed to create poseidon permutation: %w", err)
	}

	state := []frontend.Variable{
		key[0],
		key[1],
	}

	perm.Permutation(state)

	ciphertext := make([]frontend.Variable, len(plaintext)+1)

	if len(plaintext)%2 != 0 {
		return nil, fmt.Errorf("plaintext must have an even number of elements")
	}

	for i := 0; i < len(plaintext); i += 2 {
		state[0] = gadget.api.Add(state[0], plaintext[i])
		state[1] = gadget.api.Add(state[1], plaintext[i+1])

		ciphertext[i] = state[0]
		ciphertext[i+1] = state[1]

		perm.Permutation(state)
	}

	return nil, nil
}

type StreamCipherCircuit struct {
	Key        [2]frontend.Variable `gnark:"key"`
	Plaintext  []frontend.Variable  `gnark:"plaintext"`
	Ciphertext []frontend.Variable  `gnark:",public"`
}

func NewStreamCipherCircuit(plaintext_len int) *StreamCipherCircuit {
	return &StreamCipherCircuit{
		Plaintext:  make([]frontend.Variable, plaintext_len),
		Ciphertext: make([]frontend.Variable, plaintext_len+1),
	}
}

func (circuit *StreamCipherCircuit) Define(api frontend.API) error {
	gadget := NewStreamCipherGadget(api)

	ciphertext, err := gadget.Encrypt(circuit.Key, circuit.Plaintext)
	if err != nil {
		return fmt.Errorf("failed to encrypt: %w", err)
	}

	for i := 0; i < len(ciphertext); i++ {
		api.AssertIsEqual(circuit.Ciphertext[i], ciphertext[i])
	}

	return nil
}

type StreamCipher struct {
	Key [2]fr.Element
}

func (cipher *StreamCipher) Encrypt(
	plaintext []fr.Element,
) ([]fr.Element, error) {
	params := poseidonbn254.GetDefaultParameters()

	hasher := poseidonbn254.NewPermutation(params.Width, params.NbFullRounds, params.NbPartialRounds)

	if len(plaintext)%2 != 0 {
		return nil, fmt.Errorf("plaintext must have an even number of elements, chipertext must be padding to an even number of elements")
	}

	state := []fr.Element{
		cipher.Key[0],
		cipher.Key[1],
	}

	hasher.Permutation(state)

	ciphertext := make([]fr.Element, len(plaintext)+1)

	for i := 0; i < len(plaintext); i += 2 {
		ciphertext[i].Add(&state[0], &plaintext[i])
		ciphertext[i+1].Add(&state[1], &plaintext[i+1])

		state[0] = ciphertext[i]
		state[1] = ciphertext[i+1]

		hasher.Permutation(state)
	}

	// HMAC
	ciphertext[len(ciphertext)-1] = state[0]

	return ciphertext, nil
}

func (cipher *StreamCipher) Decrypt(
	ciphertext []fr.Element,
) ([]fr.Element, error) {
	params := poseidonbn254.GetDefaultParameters()

	hasher := poseidonbn254.NewPermutation(params.Width, params.NbFullRounds, params.NbPartialRounds)

	if len(ciphertext) == 0 {
		return nil, fmt.Errorf("ciphertext must have at least one element")
	}

	if (len(ciphertext)-1)%2 != 0 {
		return nil, fmt.Errorf("ciphertext must have an even number of elements, plaintext must be padding to an even number of elements")
	}

	state := []fr.Element{
		cipher.Key[0],
		cipher.Key[1],
	}

	hasher.Permutation(state)

	plaintext := make([]fr.Element, len(ciphertext)-1)

	for i := 0; i < len(ciphertext)-1; i += 2 {
		plaintext[i].Sub(&ciphertext[i], &state[0])
		plaintext[i+1].Sub(&ciphertext[i+1], &state[1])

		state[0] = ciphertext[i]
		state[1] = ciphertext[i+1]

		hasher.Permutation(state)
	}

	// HMAC
	if state[0] != ciphertext[len(ciphertext)-1] {
		return nil, fmt.Errorf("HMAC verification failed")
	}

	return plaintext, nil
}
