package builder

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon2"
)

type Cipher struct {
	SharedKey         SharedKey
	ReceiverPublicKey PublicKey
}

func NewCipher(receiverPublicKey PublicKey, senderPrivateKey PrivateKey) *Cipher {
	sharedKey := NewSharedKey(senderPrivateKey, receiverPublicKey)

	return &Cipher{
		SharedKey:         sharedKey,
		ReceiverPublicKey: receiverPublicKey,
	}
}

func (s *Cipher) Encrypt(plaintext []fr.Element) []fr.Element {
	params := poseidon2.GetDefaultParameters()
	hasher := poseidon2.NewPermutation(2, params.NbFullRounds, params.NbPartialRounds)

	state := []fr.Element{
		fr.NewElement(0),
		fr.NewElement(0),
	}
	hasher.Permutation(state)

	state[0] = s.SharedKey.SharedKey.X
	hasher.Permutation(state)

	state[0] = s.SharedKey.SharedKey.Y
	hasher.Permutation(state)

	state[0].Add(&state[0], &s.ReceiverPublicKey.PublicKey.X)
	hasher.Permutation(state)

	state[0].Add(&state[0], &s.ReceiverPublicKey.PublicKey.Y)
	hasher.Permutation(state)

	ciphertext := make([]fr.Element, len(plaintext)+1)

	for i := range plaintext {
		ciphertext[i].Add(&state[0], &plaintext[i])
		hasher.Permutation(state)

		state[0].Add(&state[0], &plaintext[i])
		hasher.Permutation(state)
	}

	// HMAC
	ciphertext[len(ciphertext)-1] = state[0]

	return ciphertext
}

func (s *Cipher) Decrypt(ciphertext []fr.Element) ([]fr.Element, error) {
	params := poseidon2.GetDefaultParameters()
	hasher := poseidon2.NewPermutation(2, params.NbFullRounds, params.NbPartialRounds)

	state := []fr.Element{
		fr.NewElement(0),
		fr.NewElement(0),
	}
	hasher.Permutation(state)

	state[0] = s.SharedKey.SharedKey.X
	hasher.Permutation(state)

	state[0] = s.SharedKey.SharedKey.Y
	hasher.Permutation(state)

	state[0].Add(&state[0], &s.ReceiverPublicKey.PublicKey.X)
	hasher.Permutation(state)

	state[0].Add(&state[0], &s.ReceiverPublicKey.PublicKey.Y)
	hasher.Permutation(state)

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
