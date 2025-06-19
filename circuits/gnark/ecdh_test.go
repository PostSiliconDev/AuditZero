package circuits_test

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	circuits "hide-pay/circuits/gnark"
)

func TestECDH_Compute(t *testing.T) {
	// Test basic ECDH computation
	ecdh := circuits.NewECDH(*big.NewInt(11111), *big.NewInt(22222))

	sharedKeyX, sharedKeyY := ecdh.Compute()

	fmt.Println(ecdh.PublicKey.X.Text(10), ecdh.PublicKey.Y.Text(10))

	assert.NotEqual(t, fr.Element{}, sharedKeyX)
	assert.NotEqual(t, fr.Element{}, sharedKeyY)
	assert.NotEqual(t, ecdh.PublicKey.X, sharedKeyX)
	assert.NotEqual(t, ecdh.PublicKey.Y, sharedKeyY)
}

func TestECDH_Compute_DifferentSecretKeys(t *testing.T) {
	// Test that different secret keys produce different shared keys
	base := circuits.NewECDH(*big.NewInt(11111), *big.NewInt(22222))

	// Different secret key
	ecdh1 := circuits.NewECDH(*big.NewInt(22222), *big.NewInt(33333))

	// Another different secret key
	ecdh2 := circuits.NewECDH(*big.NewInt(33333), *big.NewInt(44444))

	sharedKeyX0, sharedKeyY0 := base.Compute()
	sharedKeyX1, sharedKeyY1 := ecdh1.Compute()
	sharedKeyX2, sharedKeyY2 := ecdh2.Compute()

	// All results should be different
	assert.NotEqual(t, sharedKeyX0, sharedKeyX1)
	assert.NotEqual(t, sharedKeyY0, sharedKeyY1)
	assert.NotEqual(t, sharedKeyX0, sharedKeyX2)
	assert.NotEqual(t, sharedKeyY0, sharedKeyY2)
	assert.NotEqual(t, sharedKeyX1, sharedKeyX2)
	assert.NotEqual(t, sharedKeyY1, sharedKeyY2)
}

func TestECDH_Compute_Deterministic(t *testing.T) {
	// Test that same inputs produce same shared keys (deterministic)
	ecdh := circuits.NewECDH(*big.NewInt(11111), *big.NewInt(22222))

	sharedKeyX1, sharedKeyY1 := ecdh.Compute()
	sharedKeyX2, sharedKeyY2 := ecdh.Compute()
	sharedKeyX3, sharedKeyY3 := ecdh.Compute()

	assert.Equal(t, sharedKeyX1, sharedKeyX2)
	assert.Equal(t, sharedKeyY1, sharedKeyY2)
	assert.Equal(t, sharedKeyX1, sharedKeyX3)
	assert.Equal(t, sharedKeyY1, sharedKeyY3)
	assert.Equal(t, sharedKeyX2, sharedKeyX3)
	assert.Equal(t, sharedKeyY2, sharedKeyY3)
}

func TestECDH_Compute_LargeSecretKey(t *testing.T) {
	// Test large secret key
	largeKey := new(big.Int)
	largeKey.SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 16)

	ecdh := circuits.NewECDH(*largeKey, *big.NewInt(22222))

	sharedKeyX, sharedKeyY := ecdh.Compute()
	assert.NotEqual(t, fr.Element{}, sharedKeyX)
	assert.NotEqual(t, fr.Element{}, sharedKeyY)
}

func TestECDH_ToCircuit(t *testing.T) {
	// Test conversion to circuit
	ecdh := circuits.NewECDH(*big.NewInt(11111), *big.NewInt(22222))

	circuit := ecdh.ToWitness()
	require.NotNil(t, circuit)

	// Verify circuit fields
	assert.Equal(t, ecdh.PublicKey.X, circuit.PublicKeyX)
	assert.Equal(t, ecdh.PublicKey.Y, circuit.PublicKeyY)
	assert.Equal(t, ecdh.SecretKey, circuit.SecretKey)

	// Verify shared key fields should be the computed values
	expectedSharedKeyX, expectedSharedKeyY := ecdh.Compute()
	assert.Equal(t, expectedSharedKeyX, circuit.SharedKeyX)
	assert.Equal(t, expectedSharedKeyY, circuit.SharedKeyY)
}

func TestECDH_ToCircuit_Consistency(t *testing.T) {
	// Test consistency of multiple conversions
	ecdh := circuits.NewECDH(*big.NewInt(11111), *big.NewInt(22222))

	circuit1 := ecdh.ToWitness()
	circuit2 := ecdh.ToWitness()
	circuit3 := ecdh.ToWitness()

	// All conversion results should be the same
	assert.Equal(t, circuit1.PublicKeyX, circuit2.PublicKeyX)
	assert.Equal(t, circuit1.PublicKeyY, circuit2.PublicKeyY)
	assert.Equal(t, circuit1.SecretKey, circuit2.SecretKey)
	assert.Equal(t, circuit1.SharedKeyX, circuit2.SharedKeyX)
	assert.Equal(t, circuit1.SharedKeyY, circuit2.SharedKeyY)

	assert.Equal(t, circuit1.PublicKeyX, circuit3.PublicKeyX)
	assert.Equal(t, circuit1.PublicKeyY, circuit3.PublicKeyY)
	assert.Equal(t, circuit1.SecretKey, circuit3.SecretKey)
	assert.Equal(t, circuit1.SharedKeyX, circuit3.SharedKeyX)
	assert.Equal(t, circuit1.SharedKeyY, circuit3.SharedKeyY)
}

func TestECDH_Circuit_Verification(t *testing.T) {
	// Test ECDH circuit verification
	ecdh := circuits.NewECDH(*big.NewInt(11111), *big.NewInt(22222))

	circuit := circuits.NewECDHCircuit()
	require.NotNil(t, circuit)

	assert := test.NewAssert(t)

	// Create witness
	witness := ecdh.ToWitness()

	// Verify circuit
	options := test.WithCurves(ecc.BN254)
	assert.ProverSucceeded(circuit, witness, options)
}

func TestECDH_Circuit_InvalidWitness(t *testing.T) {
	// Test circuit verification with invalid witness
	ecdh := circuits.NewECDH(*big.NewInt(11111), *big.NewInt(22222))

	circuit := circuits.NewECDHCircuit()
	require.NotNil(t, circuit)

	assert := test.NewAssert(t)

	// Create invalid witness (wrong shared key values)
	witness := &circuits.ECDHCircuit{
		PublicKeyX: ecdh.PublicKey.X,
		PublicKeyY: ecdh.PublicKey.Y,
		SecretKey:  ecdh.SecretKey,
		SharedKeyX: fr.NewElement(99999), // Wrong shared key X
		SharedKeyY: fr.NewElement(88888), // Wrong shared key Y
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
			ecdh := circuits.NewECDH(tc.secretKey, tc.secretKey)

			circuit := circuits.NewECDHCircuit()
			require.NotNil(t, circuit)

			// Create witness
			witness := ecdh.ToWitness()

			// Verify circuit
			options := test.WithCurves(ecc.BN254)
			assert.ProverSucceeded(circuit, witness, options)
		})
	}
}
