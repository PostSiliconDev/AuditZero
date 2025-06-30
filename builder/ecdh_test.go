package builder_test

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/stretchr/testify/assert"

	"hide-pay/builder"
)

func TestECDH_Compute(t *testing.T) {
	// Test basic ECDH computation
	ecdh := builder.NewECDH(*big.NewInt(11144), *big.NewInt(22222))

	sharedKey := ecdh.Compute()

	assert.NotEqual(t, fr.Element{}, sharedKey.X)
	assert.NotEqual(t, fr.Element{}, sharedKey.Y)
	assert.NotEqual(t, ecdh.PublicKey.X, sharedKey.X)
	assert.NotEqual(t, ecdh.PublicKey.Y, sharedKey.Y)
}

func TestECDH_Compute_DifferentSecretKeys(t *testing.T) {
	// Test that different secret keys produce different shared keys
	base := builder.NewECDH(*big.NewInt(11111), *big.NewInt(22222))

	// Different secret key
	ecdh1 := builder.NewECDH(*big.NewInt(22222), *big.NewInt(33333))

	// Another different secret key
	ecdh2 := builder.NewECDH(*big.NewInt(33333), *big.NewInt(44444))

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
	ecdh := builder.NewECDH(*big.NewInt(11111), *big.NewInt(22222))

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

	ecdh := builder.NewECDH(*largeKey, *big.NewInt(22222))

	sharedKey := ecdh.Compute()
	assert.NotEqual(t, fr.Element{}, sharedKey.X)
	assert.NotEqual(t, fr.Element{}, sharedKey.Y)
}

func TestECDH_ToCircuit(t *testing.T) {
	// Test conversion to circuit
	ecdh := builder.NewECDH(*big.NewInt(11111), *big.NewInt(22222))

	circuit := ecdh.ToGadget()
	assert.NotNil(t, circuit)

	// Verify circuit fields
	assert.Equal(t, ecdh.PublicKey.X, circuit.PublicKey[0])
	assert.Equal(t, ecdh.PublicKey.Y, circuit.PublicKey[1])
	assert.Equal(t, ecdh.SecretKey, circuit.SecretKey)
}

func TestECDH_ToCircuit_Consistency(t *testing.T) {
	// Test consistency of multiple conversions
	ecdh := builder.NewECDH(*big.NewInt(11111), *big.NewInt(22222))

	circuit1 := ecdh.ToGadget()
	circuit2 := ecdh.ToGadget()
	circuit3 := ecdh.ToGadget()

	// All conversion results should be the same
	assert.Equal(t, circuit1.PublicKey, circuit2.PublicKey)
	assert.Equal(t, circuit1.SecretKey, circuit2.SecretKey)

	assert.Equal(t, circuit1.PublicKey, circuit3.PublicKey)
	assert.Equal(t, circuit1.SecretKey, circuit3.SecretKey)
}
