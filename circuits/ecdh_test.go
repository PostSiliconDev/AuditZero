package circuits_test

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"github.com/stretchr/testify/assert"

	"hide-pay/builder"
	"hide-pay/circuits"
)

type ECDHCircuit struct {
	PublicKey [2]frontend.Variable
	SecretKey frontend.Variable
	SharedKey [2]frontend.Variable `gnark:",public"`
}

func NewECDHCircuit() *ECDHCircuit {
	return &ECDHCircuit{}
}

func (circuit *ECDHCircuit) Define(api frontend.API) error {
	gadget := circuits.ECDHGadget{
		PublicKey: circuit.PublicKey,
		SecretKey: circuit.SecretKey,
	}

	sharedKey, err := gadget.Compute(api)
	if err != nil {
		return fmt.Errorf("failed to compute shared key: %w", err)
	}

	api.AssertIsEqual(circuit.SharedKey[0], sharedKey[0])
	api.AssertIsEqual(circuit.SharedKey[1], sharedKey[1])

	return nil
}

func TestECDH_Circuit_Verification(t *testing.T) {
	// Test ECDH circuit verification
	ecdh := builder.NewECDH(*big.NewInt(11111), *big.NewInt(22222))

	circuit := NewECDHCircuit()
	assert.NotNil(t, circuit)

	assert := test.NewAssert(t)

	// Create witness
	witness := ECDHCircuit{
		PublicKey: [2]frontend.Variable{ecdh.PublicKey.X, ecdh.PublicKey.Y},
		SecretKey: ecdh.SecretKey,
		SharedKey: [2]frontend.Variable{ecdh.Compute().X, ecdh.Compute().Y},
	}

	// Verify circuit
	options := test.WithCurves(ecc.BN254)
	assert.ProverSucceeded(circuit, &witness, options)
}

func TestECDH_Circuit_InvalidWitness(t *testing.T) {
	// Test circuit verification with invalid witness
	ecdh := builder.NewECDH(*big.NewInt(11111), *big.NewInt(22222))

	circuit := NewECDHCircuit()
	assert.NotNil(t, circuit)

	assert := test.NewAssert(t)

	// Create invalid witness (wrong shared key values)
	witness := &ECDHCircuit{
		PublicKey: [2]frontend.Variable{ecdh.PublicKey.X, ecdh.PublicKey.Y},
		SecretKey: ecdh.SecretKey,
		SharedKey: [2]frontend.Variable{fr.NewElement(99999), fr.NewElement(88888)}, // Wrong shared key X
	}

	// Verify circuit should fail
	options := test.WithCurves(ecc.BN254)
	assert.ProverFailed(circuit, witness, options)
}

func TestECDH_Circuit_DifferentInputs(t *testing.T) {
	// Test circuit verification with different inputs
	testCases := []struct {
		name       string
		publicKeyX fr.Element
		publicKeyY fr.Element
		secretKey  big.Int
	}{
		{
			name:       "Small values",
			publicKeyX: fr.NewElement(1),
			publicKeyY: fr.NewElement(2),
			secretKey:  *big.NewInt(3),
		},
		{
			name:       "Medium values",
			publicKeyX: fr.NewElement(12345),
			publicKeyY: fr.NewElement(67890),
			secretKey:  *big.NewInt(11111),
		},
		{
			name:       "Large values",
			publicKeyX: fr.NewElement(0xFFFFFFFFFFFFFFFF),
			publicKeyY: fr.NewElement(0xEEEEEEEEEEEEEEEE),
			secretKey:  *big.NewInt(0xDDDDDDDDDDDDD),
		},
	}

	assert := test.NewAssert(t)

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ecdh := builder.NewECDH(tc.secretKey, tc.secretKey)

			circuit := NewECDHCircuit()
			assert.NotNil(t, circuit)

			// Create witness
			witness := ECDHCircuit{
				PublicKey: [2]frontend.Variable{ecdh.PublicKey.X, ecdh.PublicKey.Y},
				SecretKey: ecdh.SecretKey,
				SharedKey: [2]frontend.Variable{ecdh.Compute().X, ecdh.Compute().Y},
			}

			// Verify circuit
			options := test.WithCurves(ecc.BN254)
			assert.ProverSucceeded(circuit, &witness, options)
		})
	}
}
