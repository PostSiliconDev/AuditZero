package circuits_test

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	circuits "hide-pay/circuits/gnark"
)

func TestECDH_Compute(t *testing.T) {
	// Test basic ECDH computation
	ecdh := circuits.NewECDH(*big.NewInt(11144), *big.NewInt(22222))

	sharedKey := ecdh.Compute()

	assert.NotEqual(t, fr.Element{}, sharedKey.X)
	assert.NotEqual(t, fr.Element{}, sharedKey.Y)
	assert.NotEqual(t, ecdh.PublicKey.X, sharedKey.X)
	assert.NotEqual(t, ecdh.PublicKey.Y, sharedKey.Y)
}

func TestECDH_Compute_DifferentSecretKeys(t *testing.T) {
	// Test that different secret keys produce different shared keys
	base := circuits.NewECDH(*big.NewInt(11111), *big.NewInt(22222))

	// Different secret key
	ecdh1 := circuits.NewECDH(*big.NewInt(22222), *big.NewInt(33333))

	// Another different secret key
	ecdh2 := circuits.NewECDH(*big.NewInt(33333), *big.NewInt(44444))

	sharedKey0 := base.Compute()
	sharedKey1 := ecdh1.Compute()
	sharedKey2 := ecdh2.Compute()

	// All results should be different
	assert.NotEqual(t, sharedKey0.X, sharedKey1.X)
	assert.NotEqual(t, sharedKey0.Y, sharedKey1.Y)
	assert.NotEqual(t, sharedKey0.X, sharedKey2.X)
	assert.NotEqual(t, sharedKey0.Y, sharedKey2.Y)
	assert.NotEqual(t, sharedKey1.X, sharedKey2.X)
	assert.NotEqual(t, sharedKey1.Y, sharedKey2.Y)
}

func TestECDH_Compute_Deterministic(t *testing.T) {
	// Test that same inputs produce same shared keys (deterministic)
	ecdh := circuits.NewECDH(*big.NewInt(11111), *big.NewInt(22222))

	sharedKey1 := ecdh.Compute()
	sharedKey2 := ecdh.Compute()
	sharedKey3 := ecdh.Compute()

	assert.Equal(t, sharedKey1.X, sharedKey2.X)
	assert.Equal(t, sharedKey1.Y, sharedKey2.Y)
	assert.Equal(t, sharedKey1.X, sharedKey3.X)
	assert.Equal(t, sharedKey1.Y, sharedKey3.Y)
	assert.Equal(t, sharedKey2.X, sharedKey3.X)
	assert.Equal(t, sharedKey2.Y, sharedKey3.Y)
}

func TestECDH_Compute_LargeSecretKey(t *testing.T) {
	// Test large secret key
	largeKey := new(big.Int)
	largeKey.SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 16)

	ecdh := circuits.NewECDH(*largeKey, *big.NewInt(22222))

	sharedKey := ecdh.Compute()
	assert.NotEqual(t, fr.Element{}, sharedKey.X)
	assert.NotEqual(t, fr.Element{}, sharedKey.Y)
}

func TestECDH_ToCircuit(t *testing.T) {
	// Test conversion to circuit
	ecdh := circuits.NewECDH(*big.NewInt(11111), *big.NewInt(22222))

	circuit := ecdh.ToWitness()
	require.NotNil(t, circuit)

	// Verify circuit fields
	assert.Equal(t, ecdh.PublicKey.X, circuit.PublicKey[0])
	assert.Equal(t, ecdh.PublicKey.Y, circuit.PublicKey[1])
	assert.Equal(t, ecdh.SecretKey, circuit.SecretKey)

	// Verify shared key fields should be the computed values
	expectedSharedKey := ecdh.Compute()
	assert.Equal(t, expectedSharedKey.X, circuit.SharedKey[0])
	assert.Equal(t, expectedSharedKey.Y, circuit.SharedKey[1])
}

func TestECDH_ToCircuit_Consistency(t *testing.T) {
	// Test consistency of multiple conversions
	ecdh := circuits.NewECDH(*big.NewInt(11111), *big.NewInt(22222))

	circuit1 := ecdh.ToWitness()
	circuit2 := ecdh.ToWitness()
	circuit3 := ecdh.ToWitness()

	// All conversion results should be the same
	assert.Equal(t, circuit1.PublicKey, circuit2.PublicKey)
	assert.Equal(t, circuit1.SecretKey, circuit2.SecretKey)
	assert.Equal(t, circuit1.SharedKey, circuit2.SharedKey)

	assert.Equal(t, circuit1.PublicKey, circuit3.PublicKey)
	assert.Equal(t, circuit1.SecretKey, circuit3.SecretKey)
	assert.Equal(t, circuit1.SharedKey, circuit3.SharedKey)
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
