package builder_test

import (
	"hide-pay/builder"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/stretchr/testify/assert"
)

func TestNullifier_Compute(t *testing.T) {
	// Test basic nullifier computation
	commitment, _ := builder.GenerateCommitment(12345)

	nullifier := &builder.Nullifier{
		Commitment:      *commitment,
		SpentPrivateKey: fr.NewElement(22222),
	}

	result := nullifier.Compute()

	assert.NotEqual(t, fr.Element{}, result)
	assert.NotEqual(t, nullifier.Asset, result)
	assert.NotEqual(t, nullifier.Amount, result)
	assert.NotEqual(t, nullifier.Blinding, result)
	assert.NotEqual(t, nullifier.SpentPrivateKey, result)
}

func TestNullifier_Compute_DifferentInputs(t *testing.T) {
	// Test that different inputs produce different nullifiers
	commitment, _ := builder.GenerateCommitment(12345)

	base := &builder.Nullifier{
		Commitment:      *commitment,
		SpentPrivateKey: fr.NewElement(22222),
	}

	// Different asset
	nullifier1 := &builder.Nullifier{
		Commitment: builder.Commitment{
			Asset:    fr.NewElement(54321),
			Amount:   base.Amount,
			Blinding: base.Blinding,
		},
		SpentPrivateKey: base.SpentPrivateKey,
	}

	// Different amount
	nullifier2 := &builder.Nullifier{
		Commitment: builder.Commitment{
			Asset:    base.Asset,
			Amount:   fr.NewElement(98765),
			Blinding: base.Blinding,
		},
		SpentPrivateKey: base.SpentPrivateKey,
	}

	// Different blinding
	nullifier3 := &builder.Nullifier{
		Commitment: builder.Commitment{
			Asset:    base.Asset,
			Amount:   base.Amount,
			Blinding: fr.NewElement(33333),
		},
		SpentPrivateKey: base.SpentPrivateKey,
	}

	// Different private key
	nullifier4 := &builder.Nullifier{
		Commitment: builder.Commitment{
			Asset:    base.Asset,
			Amount:   base.Amount,
			Blinding: base.Blinding,
		},
		SpentPrivateKey: fr.NewElement(44444),
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
	commitment, _ := builder.GenerateCommitment(12345)

	nullifier := &builder.Nullifier{
		Commitment:      *commitment,
		SpentPrivateKey: fr.NewElement(22222),
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
	commitment, _ := builder.GenerateCommitment(0)

	nullifier := &builder.Nullifier{
		Commitment:      *commitment,
		SpentPrivateKey: fr.NewElement(0),
	}

	result := nullifier.Compute()
	assert.NotEqual(t, fr.Element{}, result) // Even with all zero inputs, nullifier should not be zero
}

func TestNullifier_ToWitness(t *testing.T) {
	// Test conversion to circuit
	commitment, _ := builder.GenerateCommitment(12345)

	nullifier := &builder.Nullifier{
		Commitment:      *commitment,
		SpentPrivateKey: fr.NewElement(22222),
	}

	witness := nullifier.ToGadget()
	assert.NotNil(t, witness)

	// Verify circuit fields
	assert.Equal(t, nullifier.Asset, witness.Asset)
	assert.Equal(t, nullifier.Amount, witness.Amount)
	assert.Equal(t, nullifier.Blinding, witness.Blinding)
	assert.Equal(t, nullifier.SpentPrivateKey, witness.PrivateKey)

}
