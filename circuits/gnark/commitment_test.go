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

func TestCommitment_Compute(t *testing.T) {
	// Test basic commitment computation
	commitment := &circuits.Commitment{
		Asset:    fr.NewElement(12345),
		Amount:   fr.NewElement(67890),
		Blinding: fr.NewElement(11111),
	}

	result := commitment.Compute()

	assert.NotEqual(t, fr.Element{}, result)
	assert.NotEqual(t, commitment.Asset, result)
	assert.NotEqual(t, commitment.Amount, result)
	assert.NotEqual(t, commitment.Blinding, result)
}

func TestCommitment_Compute_DifferentInputs(t *testing.T) {
	// Test that different inputs produce different commitments
	commitment1 := &circuits.Commitment{
		Asset:    fr.NewElement(12345),
		Amount:   fr.NewElement(67890),
		Blinding: fr.NewElement(11111),
	}

	commitment2 := &circuits.Commitment{
		Asset:    fr.NewElement(54321), // Different asset
		Amount:   fr.NewElement(67890),
		Blinding: fr.NewElement(11111),
	}

	commitment3 := &circuits.Commitment{
		Asset:    fr.NewElement(12345),
		Amount:   fr.NewElement(98765), // Different amount
		Blinding: fr.NewElement(11111),
	}

	commitment4 := &circuits.Commitment{
		Asset:    fr.NewElement(12345),
		Amount:   fr.NewElement(67890),
		Blinding: fr.NewElement(22222), // Different blinding factor
	}

	result1 := commitment1.Compute()
	result2 := commitment2.Compute()
	result3 := commitment3.Compute()
	result4 := commitment4.Compute()

	// All results should be different
	assert.NotEqual(t, result1, result2)
	assert.NotEqual(t, result1, result3)
	assert.NotEqual(t, result1, result4)
	assert.NotEqual(t, result2, result3)
	assert.NotEqual(t, result2, result4)
	assert.NotEqual(t, result3, result4)
}

func TestCommitment_Compute_Deterministic(t *testing.T) {
	// Test that same inputs produce same commitment (deterministic)
	commitment := &circuits.Commitment{
		Asset:    fr.NewElement(12345),
		Amount:   fr.NewElement(67890),
		Blinding: fr.NewElement(11111),
	}

	result1 := commitment.Compute()
	result2 := commitment.Compute()
	result3 := commitment.Compute()

	assert.Equal(t, result1, result2)
	assert.Equal(t, result1, result3)
	assert.Equal(t, result2, result3)
}

func TestCommitment_Compute_ZeroValues(t *testing.T) {
	// Test zero value inputs
	commitment := &circuits.Commitment{
		Asset:    fr.NewElement(0),
		Amount:   fr.NewElement(0),
		Blinding: fr.NewElement(0),
	}

	result := commitment.Compute()
	assert.NotEqual(t, fr.Element{}, result) // Even with all zero inputs, commitment should not be zero
}

func TestCommitment_Compute_LargeValues(t *testing.T) {
	// Test large values
	commitment := &circuits.Commitment{
		Asset:    fr.NewElement(0xFFFFFFFFFFFFFFFF),
		Amount:   fr.NewElement(0xFFFFFFFFFFFFFFFF),
		Blinding: fr.NewElement(0xFFFFFFFFFFFFFFFF),
	}

	result := commitment.Compute()
	assert.NotEqual(t, fr.Element{}, result)
}

func TestCommitment_ToWitness(t *testing.T) {
	// Test conversion to circuit
	commitment := &circuits.Commitment{
		Asset:    fr.NewElement(12345),
		Amount:   fr.NewElement(67890),
		Blinding: fr.NewElement(11111),
	}

	witness := commitment.ToWitness()
	require.NotNil(t, witness)

	// Verify circuit fields
	assert.Equal(t, commitment.Asset, witness.Asset)
	assert.Equal(t, commitment.Amount, witness.Amount)
	assert.Equal(t, commitment.Blinding, witness.Blinding)

	// Verify commitment field should be the computed hash
	expectedCommitment := commitment.Compute()
	assert.Equal(t, expectedCommitment, witness.Commitment)
}

func TestCommitment_ToCircuit_Consistency(t *testing.T) {
	// Test consistency of multiple conversions
	commitment := &circuits.Commitment{
		Asset:    fr.NewElement(12345),
		Amount:   fr.NewElement(67890),
		Blinding: fr.NewElement(11111),
	}

	witness1 := commitment.ToWitness()
	witness2 := commitment.ToWitness()
	witness3 := commitment.ToWitness()

	// All conversion results should be the same
	assert.Equal(t, witness1.Asset, witness2.Asset)
	assert.Equal(t, witness1.Amount, witness2.Amount)
	assert.Equal(t, witness1.Blinding, witness2.Blinding)
	assert.Equal(t, witness1.Commitment, witness2.Commitment)

	assert.Equal(t, witness1.Asset, witness3.Asset)
	assert.Equal(t, witness1.Amount, witness3.Amount)
	assert.Equal(t, witness1.Blinding, witness3.Blinding)
	assert.Equal(t, witness1.Commitment, witness3.Commitment)
}

func TestCommitment_Circuit_Verification(t *testing.T) {
	// Test commitment circuit verification
	commitment := &circuits.Commitment{
		Asset:    fr.NewElement(12345),
		Amount:   fr.NewElement(67890),
		Blinding: fr.NewElement(11111),
	}

	circuit := circuits.NewCommitmentCircuit()
	require.NotNil(t, circuit)

	assert := test.NewAssert(t)

	// Create witness
	witness := commitment.ToWitness()

	// Verify circuit
	options := test.WithCurves(ecc.BN254)
	assert.ProverSucceeded(circuit, witness, options)
}

func TestCommitment_Circuit_InvalidWitness(t *testing.T) {
	// Test circuit verification with invalid witness
	commitment := &circuits.Commitment{
		Asset:    fr.NewElement(12345),
		Amount:   fr.NewElement(67890),
		Blinding: fr.NewElement(11111),
	}

	circuit := circuits.NewCommitmentCircuit()
	require.NotNil(t, circuit)

	assert := test.NewAssert(t)

	// Create invalid witness (wrong commitment value)
	witness := commitment.ToWitness()
	witness.Commitment = fr.NewElement(99999) // Wrong commitment value

	// Circuit verification should fail
	options := test.WithCurves(ecc.BN254)
	assert.ProverFailed(circuit, witness, options)
}

func TestCommitment_Circuit_DifferentInputs(t *testing.T) {
	// Test circuit verification with different inputs
	testCases := []struct {
		name       string
		asset      uint64
		amount     uint64
		blinding   uint64
		shouldPass bool
	}{
		{
			name:       "Valid commitment",
			asset:      12345,
			amount:     67890,
			blinding:   11111,
			shouldPass: true,
		},
		{
			name:       "Zero values",
			asset:      0,
			amount:     0,
			blinding:   0,
			shouldPass: true,
		},
		{
			name:       "Large values",
			asset:      0xFFFFFFFFFFFFFFFF,
			amount:     0xFFFFFFFFFFFFFFFF,
			blinding:   0xFFFFFFFFFFFFFFFF,
			shouldPass: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			commitment := &circuits.Commitment{
				Asset:    fr.NewElement(tc.asset),
				Amount:   fr.NewElement(tc.amount),
				Blinding: fr.NewElement(tc.blinding),
			}

			circuit := circuits.NewCommitmentCircuit()
			require.NotNil(t, circuit)

			witness := commitment.ToWitness()
			require.NotNil(t, witness)

			assert := test.NewAssert(t)

			options := test.WithCurves(ecc.BN254)

			if tc.shouldPass {
				assert.ProverSucceeded(circuit, witness, options)
			} else {
				assert.ProverFailed(circuit, witness, options)
			}
		})
	}
}

func TestCommitment_Compute_EdgeCases(t *testing.T) {
	// Test edge cases
	testCases := []struct {
		name     string
		asset    uint64
		amount   uint64
		blinding uint64
	}{
		{
			name:     "All zeros",
			asset:    0,
			amount:   0,
			blinding: 0,
		},
		{
			name:     "All ones",
			asset:    1,
			amount:   1,
			blinding: 1,
		},
		{
			name:     "Mixed values",
			asset:    0,
			amount:   1,
			blinding: 0,
		},
		{
			name:     "Large asset, small others",
			asset:    0xFFFFFFFFFFFFFFFF,
			amount:   1,
			blinding: 1,
		},
		{
			name:     "Small asset, large others",
			asset:    1,
			amount:   0xFFFFFFFFFFFFFFFF,
			blinding: 0xFFFFFFFFFFFFFFFF,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			commitment := &circuits.Commitment{
				Asset:    fr.NewElement(tc.asset),
				Amount:   fr.NewElement(tc.amount),
				Blinding: fr.NewElement(tc.blinding),
			}

			result := commitment.Compute()
			assert.NotEqual(t, fr.Element{}, result)

			// Verify result consistency
			result2 := commitment.Compute()
			assert.Equal(t, result, result2)
		})
	}
}
