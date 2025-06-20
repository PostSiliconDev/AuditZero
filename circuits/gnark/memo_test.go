package circuits_test

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	twistededwardbn254 "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	circuits "hide-pay/circuits/gnark"
)

func buildPublicKey(secretKey big.Int) twistededwardbn254.PointAffine {
	basePoint := twistededwardbn254.GetEdwardsCurve().Base

	return *basePoint.ScalarMultiplication(&basePoint, &secretKey)
}

func TestMemo_Encrypt(t *testing.T) {
	// Test basic memo encryption
	memo := &circuits.Memo{
		SecretKey: *big.NewInt(11111),
		PublicKey: buildPublicKey(*big.NewInt(11111)),
	}

	commitment := &circuits.Commitment{
		Asset:    fr.NewElement(12345),
		Amount:   fr.NewElement(67890),
		Blinding: fr.NewElement(11111),
	}

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
	memo := &circuits.Memo{
		SecretKey: *big.NewInt(11111),
		PublicKey: buildPublicKey(*big.NewInt(11111)),
	}

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

	_, ciphertext1, err := memo.Encrypt(*commitment1)
	require.NoError(t, err)

	_, ciphertext2, err := memo.Encrypt(*commitment2)
	require.NoError(t, err)

	// Ciphertexts should be different
	assert.NotEqual(t, ciphertext1, ciphertext2)
}

func TestMemo_Encrypt_Deterministic(t *testing.T) {
	// Test that same inputs produce same ciphertext (deterministic)
	memo := &circuits.Memo{
		SecretKey: *big.NewInt(11111),
		PublicKey: buildPublicKey(*big.NewInt(11111)),
	}

	commitment := &circuits.Commitment{
		Asset:    fr.NewElement(12345),
		Amount:   fr.NewElement(67890),
		Blinding: fr.NewElement(11111),
	}

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
	memo := &circuits.Memo{
		SecretKey: *big.NewInt(11111),
		PublicKey: buildPublicKey(*big.NewInt(11111)),
	}

	originalCommitment := &circuits.Commitment{
		Asset:    fr.NewElement(12345),
		Amount:   fr.NewElement(67890),
		Blinding: fr.NewElement(11111),
	}

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
	memo := &circuits.Memo{
		SecretKey: *big.NewInt(11111),
		PublicKey: buildPublicKey(*big.NewInt(11111)),
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

func TestMemo_EncryptDecrypt_RoundTrip(t *testing.T) {
	// Test complete encrypt-decrypt round trip
	testCases := []struct {
		name              string
		asset             fr.Element
		amount            fr.Element
		blinding          fr.Element
		secretKey         big.Int
		receiverSecretKey big.Int
	}{
		{
			name:              "Small values",
			asset:             fr.NewElement(1),
			amount:            fr.NewElement(2),
			blinding:          fr.NewElement(3),
			secretKey:         *big.NewInt(11111),
			receiverSecretKey: *big.NewInt(22222),
		},
		{
			name:              "Medium values",
			asset:             fr.NewElement(12345),
			amount:            fr.NewElement(67890),
			blinding:          fr.NewElement(11111),
			secretKey:         *big.NewInt(44444),
			receiverSecretKey: *big.NewInt(55555),
		},
		{
			name:              "Large values",
			asset:             fr.NewElement(0xFFFFFFFFFFFFFFFF),
			amount:            fr.NewElement(0xEEEEEEEEEEEEEEEE),
			blinding:          fr.NewElement(0xDDDDDDDDDDDDDDDD),
			secretKey:         *big.NewInt(0xDDDDDDDDDDDDD), // Using smaller value like in ECDH test
			receiverSecretKey: *big.NewInt(0xBBBBBBBBBBBB),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			memo := &circuits.Memo{
				SecretKey: tc.secretKey,
				PublicKey: buildPublicKey(tc.secretKey),
			}

			originalCommitment := &circuits.Commitment{
				Asset:    tc.asset,
				Amount:   tc.amount,
				Blinding: tc.blinding,
			}

			// Encrypt
			_, ciphertext, err := memo.Encrypt(*originalCommitment)
			require.NoError(t, err)

			// Decrypt
			decryptedCommitment, err := memo.Decrypt(ciphertext)
			require.NoError(t, err)

			// Verify round trip
			assert.Equal(t, originalCommitment.Asset, decryptedCommitment.Asset)
			assert.Equal(t, originalCommitment.Amount, decryptedCommitment.Amount)
			assert.Equal(t, originalCommitment.Blinding, decryptedCommitment.Blinding)
		})
	}
}

func TestMemo_Decrypt_WrongKey(t *testing.T) {
	// Test decryption with wrong key
	memo1 := &circuits.Memo{
		SecretKey: *big.NewInt(11111),
		PublicKey: buildPublicKey(*big.NewInt(11111)),
	}

	memo2 := &circuits.Memo{
		SecretKey: *big.NewInt(99999), // Different secret key
		PublicKey: buildPublicKey(*big.NewInt(99999)),
	}

	commitment := &circuits.Commitment{
		Asset:    fr.NewElement(12345),
		Amount:   fr.NewElement(67890),
		Blinding: fr.NewElement(11111),
	}

	// Encrypt with memo1
	_, ciphertext, err := memo1.Encrypt(*commitment)
	require.NoError(t, err)

	// Try to decrypt with memo2 (wrong key)
	_, err = memo2.Decrypt(ciphertext)

	assert.Error(t, err)
}

func TestMemo_EdgeCases(t *testing.T) {
	// Test edge cases
	testCases := []struct {
		name              string
		asset             fr.Element
		amount            fr.Element
		blinding          fr.Element
		secretKey         big.Int
		receiverSecretKey big.Int
	}{
		{
			name:              "All zeros",
			asset:             fr.NewElement(0),
			amount:            fr.NewElement(0),
			blinding:          fr.NewElement(0),
			secretKey:         *big.NewInt(0),
			receiverSecretKey: *big.NewInt(0),
		},
		{
			name:              "All ones",
			asset:             fr.NewElement(1),
			amount:            fr.NewElement(1),
			blinding:          fr.NewElement(1),
			secretKey:         *big.NewInt(1),
			receiverSecretKey: *big.NewInt(1),
		},
		{
			name:              "Maximum values",
			asset:             fr.NewElement(0xFFFFFFFFFFFFFFFF),
			amount:            fr.NewElement(0xFFFFFFFFFFFFFFFF),
			blinding:          fr.NewElement(0xFFFFFFFFFFFFFFFF),
			secretKey:         *big.NewInt(0xDDDDDDDDDDDDD), // Using smaller value like in ECDH test
			receiverSecretKey: *big.NewInt(0xDDDDDDDDDDDDD),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			memo := &circuits.Memo{
				SecretKey: tc.secretKey,
				PublicKey: buildPublicKey(tc.receiverSecretKey),
			}

			commitment := &circuits.Commitment{
				Asset:    tc.asset,
				Amount:   tc.amount,
				Blinding: tc.blinding,
			}

			// Test encryption
			_, ciphertext, err := memo.Encrypt(*commitment)
			require.NoError(t, err)
			require.NotNil(t, ciphertext)

			// Test decryption
			decryptedCommitment, err := memo.Decrypt(ciphertext)
			require.NoError(t, err)
			require.NotNil(t, decryptedCommitment)

			// Verify round trip
			assert.Equal(t, commitment.Asset, decryptedCommitment.Asset)
			assert.Equal(t, commitment.Amount, decryptedCommitment.Amount)
			assert.Equal(t, commitment.Blinding, decryptedCommitment.Blinding)
		})
	}
}

func TestMemo_Consistency(t *testing.T) {
	// Test consistency across multiple operations
	memo := &circuits.Memo{
		SecretKey: *big.NewInt(11111),
		PublicKey: buildPublicKey(*big.NewInt(11111)),
	}

	commitment := &circuits.Commitment{
		Asset:    fr.NewElement(12345),
		Amount:   fr.NewElement(67890),
		Blinding: fr.NewElement(11111),
	}

	// Multiple encrypt operations should produce same result
	_, ciphertext1, err := memo.Encrypt(*commitment)
	require.NoError(t, err)

	_, ciphertext2, err := memo.Encrypt(*commitment)
	require.NoError(t, err)

	_, ciphertext3, err := memo.Encrypt(*commitment)
	require.NoError(t, err)

	assert.Equal(t, ciphertext1, ciphertext2)
	assert.Equal(t, ciphertext1, ciphertext3)

	// Multiple decrypt operations should produce same result
	decrypted1, err := memo.Decrypt(ciphertext1)
	require.NoError(t, err)

	decrypted2, err := memo.Decrypt(ciphertext2)
	require.NoError(t, err)

	decrypted3, err := memo.Decrypt(ciphertext3)
	require.NoError(t, err)

	assert.Equal(t, decrypted1.Asset, decrypted2.Asset)
	assert.Equal(t, decrypted1.Amount, decrypted2.Amount)
	assert.Equal(t, decrypted1.Blinding, decrypted2.Blinding)

	assert.Equal(t, decrypted1.Asset, decrypted3.Asset)
	assert.Equal(t, decrypted1.Amount, decrypted3.Amount)
	assert.Equal(t, decrypted1.Blinding, decrypted3.Blinding)
}

func TestMemo_LargeSecretKey(t *testing.T) {
	// Test with very large secret key (like in ECDH test)
	largeKey := new(big.Int)
	largeKey.SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 16)

	memo := &circuits.Memo{
		SecretKey: *largeKey,
		PublicKey: buildPublicKey(*largeKey),
	}

	commitment := &circuits.Commitment{
		Asset:    fr.NewElement(12345),
		Amount:   fr.NewElement(67890),
		Blinding: fr.NewElement(11111),
	}

	// Test encryption
	_, ciphertext, err := memo.Encrypt(*commitment)
	require.NoError(t, err)
	require.NotNil(t, ciphertext)

	// Test decryption
	decryptedCommitment, err := memo.Decrypt(ciphertext)
	require.NoError(t, err)
	require.NotNil(t, decryptedCommitment)

	// Verify round trip
	assert.Equal(t, commitment.Asset, decryptedCommitment.Asset)
	assert.Equal(t, commitment.Amount, decryptedCommitment.Amount)
	assert.Equal(t, commitment.Blinding, decryptedCommitment.Blinding)
}

func TestMemo_Exchange_Encrypt_Decrypt(t *testing.T) {
	ephemeralSecretKey := big.NewInt(1111111)
	receiverSecretKey := big.NewInt(22222)

	receiverPublicKey := buildPublicKey(*receiverSecretKey)

	// Test exchange encrypt and decrypt
	memo1 := &circuits.Memo{
		SecretKey: *ephemeralSecretKey,
		PublicKey: receiverPublicKey,
	}

	commitment := &circuits.Commitment{
		Asset:    fr.NewElement(12345),
		Amount:   fr.NewElement(67890),
		Blinding: fr.NewElement(11111),
	}

	ephemeralPublicKey, ciphertext, err := memo1.Encrypt(*commitment)
	require.NoError(t, err)

	memo2 := &circuits.Memo{
		SecretKey: *receiverSecretKey,
		PublicKey: *ephemeralPublicKey,
	}

	decryptedCommitment, err := memo2.Decrypt(ciphertext)
	require.NoError(t, err)

	assert.Equal(t, commitment.Asset, decryptedCommitment.Asset)
	assert.Equal(t, commitment.Amount, decryptedCommitment.Amount)
	assert.Equal(t, commitment.Blinding, decryptedCommitment.Blinding)
}
