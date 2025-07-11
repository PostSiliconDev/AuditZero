package builder_test

import (
	"hide-pay/builder"
	"hide-pay/utils"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/stretchr/testify/assert"
)

func TestCommitment_Compute(t *testing.T) {
	ownerPubKey := utils.BuildPublicKey(*big.NewInt(12345))
	viewPubKey := utils.BuildPublicKey(*big.NewInt(54321))
	auditPubKey := utils.BuildPublicKey(*big.NewInt(11111))

	// Test basic commitment computation
	commitment := &builder.Commitment{
		Asset:         fr.NewElement(12345),
		Amount:        fr.NewElement(67890),
		OwnerPubKey:   ownerPubKey,
		ViewPubKey:    viewPubKey,
		AuditPubKey:   auditPubKey,
		FreezeAddress: fr.NewElement(11121314),
		Blinding:      fr.NewElement(11111),
	}

	result := commitment.Compute()

	assert.NotEqual(t, fr.Element{}, result)
	assert.NotEqual(t, commitment.Asset, result)
	assert.NotEqual(t, commitment.Amount, result)
	assert.NotEqual(t, commitment.Blinding, result)
}

func TestCommitment_Compute_DifferentInputs(t *testing.T) {
	ownerPubKey := utils.BuildPublicKey(*big.NewInt(12345))
	viewPubKey := utils.BuildPublicKey(*big.NewInt(54321))
	auditPubKey := utils.BuildPublicKey(*big.NewInt(11111))

	// Test that different inputs produce different commitments
	commitment1 := &builder.Commitment{
		Asset:         fr.NewElement(12345),
		Amount:        fr.NewElement(67890),
		OwnerPubKey:   ownerPubKey,
		ViewPubKey:    viewPubKey,
		AuditPubKey:   auditPubKey,
		FreezeAddress: fr.NewElement(11121314),
		Blinding:      fr.NewElement(11111),
	}

	commitment2 := &builder.Commitment{
		Asset:         fr.NewElement(54321), // Different asset
		Amount:        fr.NewElement(67890),
		OwnerPubKey:   ownerPubKey,
		ViewPubKey:    viewPubKey,
		AuditPubKey:   auditPubKey,
		FreezeAddress: fr.NewElement(11121314),
		Blinding:      fr.NewElement(11111),
	}

	commitment3 := &builder.Commitment{
		Asset:         fr.NewElement(12345),
		Amount:        fr.NewElement(98765), // Different amount
		OwnerPubKey:   ownerPubKey,
		ViewPubKey:    viewPubKey,
		AuditPubKey:   auditPubKey,
		FreezeAddress: fr.NewElement(11121314),
		Blinding:      fr.NewElement(11111),
	}

	commitment4 := &builder.Commitment{
		Asset:         fr.NewElement(12345),
		Amount:        fr.NewElement(67890),
		OwnerPubKey:   ownerPubKey,
		ViewPubKey:    viewPubKey,
		AuditPubKey:   auditPubKey,
		FreezeAddress: fr.NewElement(11121314),
		Blinding:      fr.NewElement(22222), // Different blinding factor
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
	ownerPubKey := utils.BuildPublicKey(*big.NewInt(12345))
	viewPubKey := utils.BuildPublicKey(*big.NewInt(54321))
	auditPubKey := utils.BuildPublicKey(*big.NewInt(11111))

	// Test that same inputs produce same commitment (deterministic)
	commitment := &builder.Commitment{
		Asset:         fr.NewElement(12345),
		Amount:        fr.NewElement(67890),
		OwnerPubKey:   ownerPubKey,
		ViewPubKey:    viewPubKey,
		AuditPubKey:   auditPubKey,
		FreezeAddress: fr.NewElement(11121314),
		Blinding:      fr.NewElement(11111),
	}

	result1 := commitment.Compute()
	result2 := commitment.Compute()
	result3 := commitment.Compute()

	assert.Equal(t, result1, result2)
	assert.Equal(t, result1, result3)
	assert.Equal(t, result2, result3)
}

func TestCommitment_Compute_ZeroValues(t *testing.T) {
	ownerPubKey := utils.BuildPublicKey(*big.NewInt(0))
	viewPubKey := utils.BuildPublicKey(*big.NewInt(0))
	auditPubKey := utils.BuildPublicKey(*big.NewInt(0))

	// Test zero value inputs
	commitment := &builder.Commitment{
		Asset:         fr.NewElement(0),
		Amount:        fr.NewElement(0),
		OwnerPubKey:   ownerPubKey,
		ViewPubKey:    viewPubKey,
		AuditPubKey:   auditPubKey,
		FreezeAddress: fr.NewElement(0),
		Blinding:      fr.NewElement(0),
	}

	result := commitment.Compute()
	assert.NotEqual(t, fr.Element{}, result) // Even with all zero inputs, commitment should not be zero
}

func TestCommitment_Compute_LargeValues(t *testing.T) {
	ownerPubKey := utils.BuildPublicKey(*big.NewInt(0x7FFFFFFFFFFFFFFF))
	viewPubKey := utils.BuildPublicKey(*big.NewInt(0x7FFFFFFFFFFFFFFF))
	auditPubKey := utils.BuildPublicKey(*big.NewInt(0x7FFFFFFFFFFFFFFF))

	// Test large values
	commitment := &builder.Commitment{
		Asset:         fr.NewElement(0xFFFFFFFFFFFFFFFF),
		Amount:        fr.NewElement(0xFFFFFFFFFFFFFFFF),
		OwnerPubKey:   ownerPubKey,
		ViewPubKey:    viewPubKey,
		AuditPubKey:   auditPubKey,
		FreezeAddress: fr.NewElement(0xFFFFFFFFFFFFFFFF),
		Blinding:      fr.NewElement(0xFFFFFFFFFFFFFFFF),
	}

	result := commitment.Compute()
	assert.NotEqual(t, fr.Element{}, result)
}

func TestCommitment_ToCircuit_Consistency(t *testing.T) {
	ownerPubKey := utils.BuildPublicKey(*big.NewInt(12345))
	viewPubKey := utils.BuildPublicKey(*big.NewInt(54321))
	auditPubKey := utils.BuildPublicKey(*big.NewInt(11111))

	// Test consistency of multiple conversions
	commitment := &builder.Commitment{
		Asset:         fr.NewElement(12345),
		Amount:        fr.NewElement(67890),
		OwnerPubKey:   ownerPubKey,
		ViewPubKey:    viewPubKey,
		AuditPubKey:   auditPubKey,
		FreezeAddress: fr.NewElement(11121314),
		Blinding:      fr.NewElement(11111),
	}

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

func TestCommitment_Compute_EdgeCases(t *testing.T) {
	// Test edge cases
	testCases := []struct {
		name          string
		asset         uint64
		amount        uint64
		ownerPubKey   uint64
		viewPubKey    uint64
		auditPubKey   uint64
		freezeAddress uint64
		blinding      uint64
	}{
		{
			name:          "All zeros",
			asset:         0,
			amount:        0,
			ownerPubKey:   0,
			viewPubKey:    0,
			auditPubKey:   0,
			freezeAddress: 0,
			blinding:      0,
		},
		{
			name:          "All ones",
			asset:         1,
			amount:        1,
			ownerPubKey:   1,
			viewPubKey:    1,
			auditPubKey:   1,
			freezeAddress: 1,
			blinding:      1,
		},
		{
			name:          "Mixed values",
			asset:         0,
			amount:        1,
			ownerPubKey:   0,
			viewPubKey:    1,
			auditPubKey:   0,
			freezeAddress: 1,
			blinding:      0,
		},
		{
			name:          "Large asset, small others",
			asset:         0xFFFFFFFFFFFFFFFF,
			amount:        1,
			ownerPubKey:   1,
			viewPubKey:    1,
			auditPubKey:   1,
			freezeAddress: 1,
			blinding:      1,
		},
		{
			name:          "Small asset, large others",
			asset:         1,
			amount:        0xFFFFFFFFFFFFFFFF,
			ownerPubKey:   0x7FFFFFFFFFFFFFFF,
			viewPubKey:    0x7FFFFFFFFFFFFFFF,
			auditPubKey:   0x7FFFFFFFFFFFFFFF,
			freezeAddress: 0xFFFFFFFFFFFFFFFF,
			blinding:      0xFFFFFFFFFFFFFFFF,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ownerPubKey := utils.BuildPublicKey(*big.NewInt(int64(tc.ownerPubKey)))
			viewPubKey := utils.BuildPublicKey(*big.NewInt(int64(tc.viewPubKey)))
			auditPubKey := utils.BuildPublicKey(*big.NewInt(int64(tc.auditPubKey)))

			commitment := &builder.Commitment{
				Asset:         fr.NewElement(tc.asset),
				Amount:        fr.NewElement(tc.amount),
				OwnerPubKey:   ownerPubKey,
				ViewPubKey:    viewPubKey,
				AuditPubKey:   auditPubKey,
				FreezeAddress: fr.NewElement(tc.freezeAddress),
				Blinding:      fr.NewElement(tc.blinding),
			}

			result := commitment.Compute()
			assert.NotEqual(t, fr.Element{}, result)

			// Verify result consistency
			result2 := commitment.Compute()
			assert.Equal(t, result, result2)
		})
	}
}
