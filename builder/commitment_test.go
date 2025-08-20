package builder_test

import (
	"hide-pay/builder"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/stretchr/testify/assert"
)

func TestCommitment_Compute(t *testing.T) {
	commitment, _ := builder.GenerateCommitment(12345)

	result := commitment.Compute()

	assert.NotEqual(t, fr.Element{}, result)
	assert.NotEqual(t, commitment.Asset, result)
	assert.NotEqual(t, commitment.Amount, result)
	assert.NotEqual(t, commitment.Blinding, result)
}

func TestCommitment_Compute_DifferentInputs(t *testing.T) {
	commitment1, _ := builder.GenerateCommitment(12345)
	commitment2, _ := builder.GenerateCommitment(54321)
	commitment3, _ := builder.GenerateCommitment(11111)
	commitment4, _ := builder.GenerateCommitment(22222)

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
	commitment, _ := builder.GenerateCommitment(12345)

	result1 := commitment.Compute()
	result2 := commitment.Compute()
	result3 := commitment.Compute()

	assert.Equal(t, result1, result2)
	assert.Equal(t, result1, result3)
	assert.Equal(t, result2, result3)
}

func TestCommitment_Compute_ZeroValues(t *testing.T) {
	commitment, _ := builder.GenerateCommitment(0)
	result := commitment.Compute()
	assert.NotEqual(t, fr.Element{}, result) // Even with all zero inputs, commitment should not be zero
}

func TestCommitment_ToCircuit_Consistency(t *testing.T) {
	commitment, _ := builder.GenerateCommitment(12345)

	witness1 := commitment.ToGadget()
	witness2 := commitment.ToGadget()
	witness3 := commitment.ToGadget()

	// All conversion results should be the same
	assert.Equal(t, witness1.Asset, witness2.Asset)
	assert.Equal(t, witness1.Amount, witness2.Amount)
	assert.Equal(t, witness1.Blinding, witness2.Blinding)

	assert.Equal(t, witness1.Asset, witness3.Asset)
	assert.Equal(t, witness1.Amount, witness3.Amount)
	assert.Equal(t, witness1.Blinding, witness3.Blinding)
}
