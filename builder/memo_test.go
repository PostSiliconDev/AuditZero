package builder_test

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"hide-pay/builder"
	"hide-pay/utils"
)

func TestMemo_Encrypt(t *testing.T) {
	// Test basic memo encryption
	memo := &builder.Memo{
		SecretKey: *big.NewInt(11111),
		PublicKey: utils.BuildPublicKey(*big.NewInt(11111)),
	}

	commitment := GenerateCommitment(12345)

	_, ciphertext, err := memo.Encrypt(*commitment)
	require.NoError(t, err)
	require.NotNil(t, ciphertext)
	assert.NotEmpty(t, ciphertext)

	// Verify ciphertext is different from plaintext
	assert.NotEqual(t, commitment.Asset, ciphertext[0])
	assert.NotEqual(t, commitment.Amount, ciphertext[1])
	assert.NotEqual(t, commitment.Blinding, ciphertext[2])
}

func TestMemo_Encrypt_DifferentInputs(t *testing.T) {
	// Test that different inputs produce different ciphertexts
	memo := &builder.Memo{
		SecretKey: *big.NewInt(11111),
		PublicKey: utils.BuildPublicKey(*big.NewInt(11111)),
	}

	commitment1 := GenerateCommitment(12345)

	commitment2 := GenerateCommitment(54321)

	_, ciphertext1, err := memo.Encrypt(*commitment1)
	require.NoError(t, err)

	_, ciphertext2, err := memo.Encrypt(*commitment2)
	require.NoError(t, err)

	// Ciphertexts should be different
	assert.NotEqual(t, ciphertext1, ciphertext2)
}

func TestMemo_Encrypt_Deterministic(t *testing.T) {
	// Test that same inputs produce same ciphertext (deterministic)
	memo := &builder.Memo{
		SecretKey: *big.NewInt(11111),
		PublicKey: utils.BuildPublicKey(*big.NewInt(11111)),
	}

	commitment := GenerateCommitment(12345)

	_, ciphertext1, err := memo.Encrypt(*commitment)
	require.NoError(t, err)

	_, ciphertext2, err := memo.Encrypt(*commitment)
	require.NoError(t, err)

	_, ciphertext3, err := memo.Encrypt(*commitment)
	require.NoError(t, err)

	// All ciphertexts should be the same
	assert.Equal(t, ciphertext1, ciphertext2)
	assert.Equal(t, ciphertext1, ciphertext3)
	assert.Equal(t, ciphertext2, ciphertext3)
}

func TestMemo_Decrypt(t *testing.T) {
	// Test basic memo decryption
	memo := &builder.Memo{
		SecretKey: *big.NewInt(11111),
		PublicKey: utils.BuildPublicKey(*big.NewInt(11111)),
	}

	originalCommitment := GenerateCommitment(12345)

	// Encrypt first
	_, ciphertext, err := memo.Encrypt(*originalCommitment)
	require.NoError(t, err)

	// Then decrypt
	decryptedCommitment, err := memo.Decrypt(ciphertext)
	require.NoError(t, err)
	require.NotNil(t, decryptedCommitment)

	// Verify decrypted values match original
	assert.Equal(t, originalCommitment.Asset, decryptedCommitment.Asset)
	assert.Equal(t, originalCommitment.Amount, decryptedCommitment.Amount)
	assert.Equal(t, originalCommitment.Blinding, decryptedCommitment.Blinding)
}

func TestMemo_Decrypt_InvalidCiphertext(t *testing.T) {
	// Test decryption with invalid ciphertext
	memo := &builder.Memo{
		SecretKey: *big.NewInt(11111),
		PublicKey: utils.BuildPublicKey(*big.NewInt(11111)),
	}

	// Invalid ciphertext (wrong length)
	invalidCiphertext := []fr.Element{
		fr.NewElement(12345),
		fr.NewElement(67890),
		// Missing elements
	}

	_, err := memo.Decrypt(invalidCiphertext)
	assert.Error(t, err)
}

func TestMemo_Decrypt_WrongKey(t *testing.T) {
	// Test decryption with wrong key
	memo1 := &builder.Memo{
		SecretKey: *big.NewInt(11111),
		PublicKey: utils.BuildPublicKey(*big.NewInt(11111)),
	}

	memo2 := &builder.Memo{
		SecretKey: *big.NewInt(99999), // Different secret key
		PublicKey: utils.BuildPublicKey(*big.NewInt(99999)),
	}

	commitment := GenerateCommitment(12345)

	// Encrypt with memo1
	_, ciphertext, err := memo1.Encrypt(*commitment)
	require.NoError(t, err)

	// Try to decrypt with memo2 (wrong key)
	_, err = memo2.Decrypt(ciphertext)

	assert.Error(t, err)
}
