package circuits_test

import (
	circuits "hide-pay/circuits/gnark"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNullifier_Compute(t *testing.T) {
	// Test basic nullifier computation
	nullifier := &circuits.Nullifier{
		Commitment: circuits.Commitment{
			Asset:    fr.NewElement(12345),
			Amount:   fr.NewElement(67890),
			Blinding: fr.NewElement(11111),
		},
		PrivateKey: fr.NewElement(22222),
	}

	result := nullifier.Compute()

	assert.NotEqual(t, fr.Element{}, result)
	assert.NotEqual(t, nullifier.Asset, result)
	assert.NotEqual(t, nullifier.Amount, result)
	assert.NotEqual(t, nullifier.Blinding, result)
	assert.NotEqual(t, nullifier.PrivateKey, result)
}

func TestNullifier_Compute_DifferentInputs(t *testing.T) {
	// Test that different inputs produce different nullifiers
	base := &circuits.Nullifier{
		Commitment: circuits.Commitment{
			Asset:    fr.NewElement(12345),
			Amount:   fr.NewElement(67890),
			Blinding: fr.NewElement(11111),
		},
		PrivateKey: fr.NewElement(22222),
	}

	// Different asset
	nullifier1 := &circuits.Nullifier{
		Commitment: circuits.Commitment{
			Asset:    fr.NewElement(54321),
			Amount:   base.Amount,
			Blinding: base.Blinding,
		},
		PrivateKey: base.PrivateKey,
	}

	// Different amount
	nullifier2 := &circuits.Nullifier{
		Commitment: circuits.Commitment{
			Asset:    base.Asset,
			Amount:   fr.NewElement(98765),
			Blinding: base.Blinding,
		},
		PrivateKey: base.PrivateKey,
	}

	// Different blinding
	nullifier3 := &circuits.Nullifier{
		Commitment: circuits.Commitment{
			Asset:    base.Asset,
			Amount:   base.Amount,
			Blinding: fr.NewElement(33333),
		},
		PrivateKey: base.PrivateKey,
	}

	// Different private key
	nullifier4 := &circuits.Nullifier{
		Commitment: circuits.Commitment{
			Asset:    base.Asset,
			Amount:   base.Amount,
			Blinding: base.Blinding,
		},
		PrivateKey: fr.NewElement(44444),
	}

	result0 := base.Compute()
	result1 := nullifier1.Compute()
	result2 := nullifier2.Compute()
	result3 := nullifier3.Compute()
	result4 := nullifier4.Compute()

	// All results should be different
	assert.NotEqual(t, result0, result1)
	assert.NotEqual(t, result0, result2)
	assert.NotEqual(t, result0, result3)
	assert.NotEqual(t, result0, result4)
	assert.NotEqual(t, result1, result2)
	assert.NotEqual(t, result1, result3)
	assert.NotEqual(t, result1, result4)
	assert.NotEqual(t, result2, result3)
	assert.NotEqual(t, result2, result4)
	assert.NotEqual(t, result3, result4)
}

func TestNullifier_Compute_Deterministic(t *testing.T) {
	// Test that same inputs produce same nullifier (deterministic)
	nullifier := &circuits.Nullifier{
		Commitment: circuits.Commitment{
			Asset:    fr.NewElement(12345),
			Amount:   fr.NewElement(67890),
			Blinding: fr.NewElement(11111),
		},
		PrivateKey: fr.NewElement(22222),
	}

	result1 := nullifier.Compute()
	result2 := nullifier.Compute()
	result3 := nullifier.Compute()

	assert.Equal(t, result1, result2)
	assert.Equal(t, result1, result3)
	assert.Equal(t, result2, result3)
}

func TestNullifier_Compute_ZeroValues(t *testing.T) {
	// Test zero value inputs
	nullifier := &circuits.Nullifier{
		Commitment: circuits.Commitment{
			Asset:    fr.NewElement(0),
			Amount:   fr.NewElement(0),
			Blinding: fr.NewElement(0),
		},
		PrivateKey: fr.NewElement(0),
	}

	result := nullifier.Compute()
	assert.NotEqual(t, fr.Element{}, result) // Even with all zero inputs, nullifier should not be zero
}

func TestNullifier_Compute_LargeValues(t *testing.T) {
	// Test large values
	nullifier := &circuits.Nullifier{
		Commitment: circuits.Commitment{
			Asset:    fr.NewElement(0xFFFFFFFFFFFFFFFF),
			Amount:   fr.NewElement(0xFFFFFFFFFFFFFFFF),
			Blinding: fr.NewElement(0xFFFFFFFFFFFFFFFF),
		},
		PrivateKey: fr.NewElement(0xFFFFFFFFFFFFFFFF),
	}

	result := nullifier.Compute()
	assert.NotEqual(t, fr.Element{}, result)
}

func TestNullifier_ToWitness(t *testing.T) {
	// Test conversion to circuit
	nullifier := &circuits.Nullifier{
		Commitment: circuits.Commitment{
			Asset:    fr.NewElement(12345),
			Amount:   fr.NewElement(67890),
			Blinding: fr.NewElement(11111),
		},
		PrivateKey: fr.NewElement(22222),
	}

	witness := nullifier.ToWitness()
	require.NotNil(t, witness)

	// Verify circuit fields
	assert.Equal(t, nullifier.Asset, witness.Asset)
	assert.Equal(t, nullifier.Amount, witness.Amount)
	assert.Equal(t, nullifier.Blinding, witness.Blinding)
	assert.Equal(t, nullifier.PrivateKey, witness.PrivateKey)

	// Verify nullifier field should be the computed hash
	expectedNullifier := nullifier.Compute()
	assert.Equal(t, expectedNullifier, witness.Nullifier)
}

func TestNullifier_ToWitness_Consistency(t *testing.T) {
	// Test consistency of multiple conversions
	nullifier := &circuits.Nullifier{
		Commitment: circuits.Commitment{
			Asset:    fr.NewElement(12345),
			Amount:   fr.NewElement(67890),
			Blinding: fr.NewElement(11111),
		},
		PrivateKey: fr.NewElement(22222),
	}

	witness1 := nullifier.ToWitness()
	witness2 := nullifier.ToWitness()
	witness3 := nullifier.ToWitness()

	// All conversion results should be the same
	assert.Equal(t, witness1.Asset, witness2.Asset)
	assert.Equal(t, witness1.Amount, witness2.Amount)
	assert.Equal(t, witness1.Blinding, witness2.Blinding)
	assert.Equal(t, witness1.PrivateKey, witness2.PrivateKey)
	assert.Equal(t, witness1.Nullifier, witness2.Nullifier)

	assert.Equal(t, witness1.Asset, witness3.Asset)
	assert.Equal(t, witness1.Amount, witness3.Amount)
	assert.Equal(t, witness1.Blinding, witness3.Blinding)
	assert.Equal(t, witness1.PrivateKey, witness3.PrivateKey)
	assert.Equal(t, witness1.Nullifier, witness3.Nullifier)
}

func TestNullifier_Circuit_Verification(t *testing.T) {
	// Test nullifier circuit verification
	nullifier := &circuits.Nullifier{
		Commitment: circuits.Commitment{
			Asset:    fr.NewElement(12345),
			Amount:   fr.NewElement(67890),
			Blinding: fr.NewElement(11111),
		},
		PrivateKey: fr.NewElement(22222),
	}

	circuit := circuits.NewNullifierCircuit()
	require.NotNil(t, circuit)

	assert := test.NewAssert(t)

	// Create witness
	witness := nullifier.ToWitness()

	// Verify circuit
	options := test.WithCurves(ecc.BN254)
	assert.ProverSucceeded(circuit, witness, options)
}

func TestNullifier_Circuit_InvalidWitness(t *testing.T) {
	// Test circuit verification with invalid witness
	nullifier := &circuits.Nullifier{
		Commitment: circuits.Commitment{
			Asset:    fr.NewElement(12345),
			Amount:   fr.NewElement(67890),
			Blinding: fr.NewElement(11111),
		},
		PrivateKey: fr.NewElement(22222),
	}

	circuit := circuits.NewNullifierCircuit()
	require.NotNil(t, circuit)

	assert := test.NewAssert(t)

	// Create invalid witness (wrong nullifier value)
	witness := nullifier.ToWitness()
	witness.Nullifier = fr.NewElement(99999) // Wrong nullifier value

	// Verify circuit should fail
	options := test.WithCurves(ecc.BN254)
	assert.ProverFailed(circuit, witness, options)
}

func TestNullifier_Circuit_DifferentInputs(t *testing.T) {
	// Test circuit verification with different input combinations
	testCases := []struct {
		name       string
		asset      uint64
		amount     uint64
		blinding   uint64
		privateKey uint64
	}{
		{"small_values", 1, 2, 3, 4},
		{"medium_values", 1000, 2000, 3000, 4000},
		{"large_values", 1000000, 2000000, 3000000, 4000000},
		{"mixed_values", 123, 456789, 987, 654321},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			nullifier := &circuits.Nullifier{
				Commitment: circuits.Commitment{
					Asset:    fr.NewElement(tc.asset),
					Amount:   fr.NewElement(tc.amount),
					Blinding: fr.NewElement(tc.blinding),
				},
				PrivateKey: fr.NewElement(tc.privateKey),
			}

			circuit := circuits.NewNullifierCircuit()
			require.NotNil(t, circuit)

			assert := test.NewAssert(t)

			witness := nullifier.ToWitness()

			options := test.WithCurves(ecc.BN254)
			assert.ProverSucceeded(circuit, witness, options)
		})
	}
}

func TestNullifier_ToCommitment(t *testing.T) {
	// Test conversion to commitment
	nullifier := &circuits.Nullifier{
		Commitment: circuits.Commitment{
			Asset:    fr.NewElement(12345),
			Amount:   fr.NewElement(67890),
			Blinding: fr.NewElement(11111),
		},
		PrivateKey: fr.NewElement(22222),
	}

	commitment := nullifier.ToCommitment()
	require.NotNil(t, commitment)

	// Verify commitment fields (should not include private key)
	assert.Equal(t, nullifier.Asset, commitment.Asset)
	assert.Equal(t, nullifier.Amount, commitment.Amount)
	assert.Equal(t, nullifier.Blinding, commitment.Blinding)
}

func TestNullifier_Compute_EdgeCases(t *testing.T) {
	// Test edge cases
	testCases := []struct {
		name       string
		asset      uint64
		amount     uint64
		blinding   uint64
		privateKey uint64
	}{
		{"all_zeros", 0, 0, 0, 0},
		{"all_ones", 1, 1, 1, 1},
		{"max_values", 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF},
		{"mixed_zeros", 0, 12345, 0, 67890},
		{"mixed_max", 0xFFFFFFFFFFFFFFFF, 12345, 0xFFFFFFFFFFFFFFFF, 67890},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			nullifier := &circuits.Nullifier{
				Commitment: circuits.Commitment{
					Asset:    fr.NewElement(tc.asset),
					Amount:   fr.NewElement(tc.amount),
					Blinding: fr.NewElement(tc.blinding),
				},
				PrivateKey: fr.NewElement(tc.privateKey),
			}

			result := nullifier.Compute()
			assert.NotEqual(t, fr.Element{}, result)

			// Test circuit verification for edge cases
			circuit := circuits.NewNullifierCircuit()
			require.NotNil(t, circuit)

			assert := test.NewAssert(t)

			witness := nullifier.ToWitness()

			options := test.WithCurves(ecc.BN254)
			assert.ProverSucceeded(circuit, witness, options)
		})
	}
}

func TestNullifier_Uniqueness(t *testing.T) {
	// Test that nullifiers are unique for different inputs
	base := &circuits.Nullifier{
		Commitment: circuits.Commitment{
			Asset:    fr.NewElement(12345),
			Amount:   fr.NewElement(67890),
			Blinding: fr.NewElement(11111),
		},
		PrivateKey: fr.NewElement(22222),
	}

	baseResult := base.Compute()

	// Test with same inputs but different private key (should produce different nullifier)
	nullifierSameInputs := &circuits.Nullifier{
		Commitment: circuits.Commitment{
			Asset:    base.Asset,
			Amount:   base.Amount,
			Blinding: base.Blinding,
		},
		PrivateKey: fr.NewElement(33333), // Different private key
	}

	sameInputsResult := nullifierSameInputs.Compute()
	assert.NotEqual(t, baseResult, sameInputsResult)

	// Test with same private key but different other inputs
	nullifierSameKey := &circuits.Nullifier{
		Commitment: circuits.Commitment{
			Asset:    fr.NewElement(54321), // Different asset
			Amount:   base.Amount,
			Blinding: base.Blinding,
		},
		PrivateKey: base.PrivateKey,
	}

	sameKeyResult := nullifierSameKey.Compute()
	assert.NotEqual(t, baseResult, sameKeyResult)
	assert.NotEqual(t, sameInputsResult, sameKeyResult)
}
