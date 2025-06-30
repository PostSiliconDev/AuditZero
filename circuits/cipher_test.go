package circuits_test

import (
	"fmt"
	"hide-pay/builder"
	"hide-pay/circuits"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"github.com/stretchr/testify/require"
)

type StreamCipherCircuit struct {
	Key            [2]frontend.Variable
	Ad             []frontend.Variable
	Plaintext      []frontend.Variable
	CiphertextHash frontend.Variable `gnark:",public"`
}

func NewStreamCipherCircuit(adSize int, plaintextSize int) *StreamCipherCircuit {
	return &StreamCipherCircuit{
		Ad:        make([]frontend.Variable, adSize),
		Plaintext: make([]frontend.Variable, plaintextSize),
	}
}

func (circuit *StreamCipherCircuit) Define(api frontend.API) error {
	gadget := circuits.StreamCipherGadget{
		Key: circuit.Key,
	}

	ciphertext, err := gadget.Encrypt(api, circuit.Ad, circuit.Plaintext)
	if err != nil {
		return fmt.Errorf("failed to encrypt: %w", err)
	}

	api.AssertIsEqual(circuit.CiphertextHash, ciphertext)

	return nil
}

func TestStreamCipher_ToCircuit(t *testing.T) {
	key := fr.NewElement(12345)
	nonce := fr.NewElement(67890)

	cipher := &builder.StreamCipher{
		Key: [2]fr.Element{key, nonce},
	}

	ad := []fr.Element{
		fr.NewElement(10),
		fr.NewElement(20),
	}

	plaintext := []fr.Element{
		fr.NewElement(100),
		fr.NewElement(200),
		fr.NewElement(300),
		fr.NewElement(400),
	}

	ciphertext, err := cipher.Encrypt(ad, plaintext)
	require.NoError(t, err)

	circuit := NewStreamCipherCircuit(len(ad), len(plaintext))
	require.NotNil(t, circuit)

	assert := test.NewAssert(t)

	ad_witness := make([]frontend.Variable, len(ad))
	for i := range ad {
		ad_witness[i] = ad[i]
	}

	plaintext_witness := make([]frontend.Variable, len(plaintext))
	for i := range plaintext {
		plaintext_witness[i] = plaintext[i]
	}

	witness := StreamCipherCircuit{
		Key:            cipher.ToGadget().Key,
		Ad:             ad_witness,
		Plaintext:      plaintext_witness,
		CiphertextHash: ciphertext[len(ciphertext)-1],
	}

	assert.ProverSucceeded(circuit, &witness, test.WithCurves(ecc.BN254))
}
