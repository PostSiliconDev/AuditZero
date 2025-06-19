package circuits

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	poseidonbn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon2"
	"github.com/consensys/gnark/frontend"
	poseidon "github.com/consensys/gnark/std/permutation/poseidon2"
)

type StreamCipherCircuit struct {
	Key        frontend.Variable
	Nonce      frontend.Variable
	Plaintext  []frontend.Variable
	Ciphertext []frontend.Variable `gnark:",public"`
}

func (circuit *StreamCipherCircuit) Define(api frontend.API) error {
	params := poseidonbn254.GetDefaultParameters()
	perm, err := poseidon.NewPoseidon2FromParameters(api, params.Width, params.NbFullRounds, params.NbPartialRounds)
	if err != nil {
		return err
	}

	state := []frontend.Variable{
		circuit.Key,
		circuit.Nonce,
	}

	perm.Permutation(state)

	if len(circuit.Plaintext) != len(circuit.Ciphertext) {
		return fmt.Errorf("plaintext and ciphertext must have the same length")
	}

	if len(circuit.Plaintext)%2 != 0 {
		return fmt.Errorf("plaintext must have an even number of elements")
	}

	for i := 0; i < len(circuit.Plaintext); i += 2 {
		state[0] = api.Xor(state[0], circuit.Plaintext[i])
		state[1] = api.Xor(state[1], circuit.Plaintext[i+1])

		api.AssertIsEqual(state[0], circuit.Ciphertext[i])
		api.AssertIsEqual(state[1], circuit.Ciphertext[i+1])

		perm.Permutation(state)
	}

	return nil
}

type StreamCipher struct {
	Key   fr.Element
	Nonce fr.Element
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
		cipher.Key,
		cipher.Nonce,
	}

	hasher.Permutation(state)

	ciphertext := make([]fr.Element, len(plaintext)+1)

	for i := 0; i < len(plaintext); i += 2 {
		state[0] = xor(state[0], plaintext[i])
		state[1] = xor(state[1], plaintext[i+1])

		ciphertext[i] = state[0]
		ciphertext[i+1] = state[1]

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
		cipher.Key,
		cipher.Nonce,
	}

	hasher.Permutation(state)

	plaintext := make([]fr.Element, len(ciphertext)-1)

	for i := 0; i < len(ciphertext)-1; i += 2 {
		plaintext[i] = xor(state[0], ciphertext[i])
		plaintext[i+1] = xor(state[1], ciphertext[i+1])

		state[0] = xor(state[0], plaintext[i])
		state[1] = xor(state[1], plaintext[i+1])

		hasher.Permutation(state)
	}

	// HMAC
	if state[0] != ciphertext[len(ciphertext)-1] {
		return nil, fmt.Errorf("HMAC verification failed")
	}

	return plaintext, nil
}

func xor(a, b fr.Element) fr.Element {
	aBitInt := new(big.Int)
	bBitInt := new(big.Int)

	a.BigInt(aBitInt)
	b.BigInt(bBitInt)

	aBitInt.Xor(aBitInt, bBitInt)

	res := fr.Element{}
	res.SetBigInt(aBitInt)

	return res
}
