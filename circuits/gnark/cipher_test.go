package circuits_test

import (
	circuits "hide-pay/circuits/gnark"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStreamCipher_EncryptDecrypt(t *testing.T) {
	key := fr.NewElement(12345)
	nonce := fr.NewElement(67890)

	cipher := &circuits.StreamCipher{
		Key: [2]fr.Element{key, nonce},
	}

	ad := []fr.Element{
		fr.NewElement(10),
		fr.NewElement(20),
	}

	plaintext := []fr.Element{
		fr.NewElement(100),
		fr.NewElement(200),
		fr.NewElement(300),
		fr.NewElement(400),
	}

	ciphertext, err := cipher.Encrypt(ad, plaintext)
	require.NoError(t, err)
	assert.NotNil(t, ciphertext)
	assert.Equal(t, len(plaintext)+1, len(ciphertext)) // +1 for HMAC

	decrypted, err := cipher.Decrypt(ad, ciphertext)
	require.NoError(t, err)
	assert.NotNil(t, decrypted)
	assert.Equal(t, len(plaintext), len(decrypted))

	for i := 0; i < len(plaintext); i++ {
		assert.Equal(t, plaintext[i], decrypted[i])
	}
}

func TestStreamCipher_EncryptDecrypt_EmptyPlaintext(t *testing.T) {
	key := fr.NewElement(12345)
	nonce := fr.NewElement(67890)

	cipher := &circuits.StreamCipher{
		Key: [2]fr.Element{key, nonce},
	}

	ad := []fr.Element{}

	plaintext := []fr.Element{}

	ciphertext, err := cipher.Encrypt(ad, plaintext)
	require.NoError(t, err)
	assert.Equal(t, 1, len(ciphertext))

	decrypted, err := cipher.Decrypt(ad, ciphertext)
	require.NoError(t, err)
	assert.Equal(t, 0, len(decrypted))
}

func TestStreamCipher_Decrypt_InvalidHMAC(t *testing.T) {
	key := fr.NewElement(12345)
	nonce := fr.NewElement(67890)

	cipher := &circuits.StreamCipher{
		Key: [2]fr.Element{key, nonce},
	}

	ad := []fr.Element{
		fr.NewElement(10),
		fr.NewElement(20),
	}

	plaintext := []fr.Element{
		fr.NewElement(100),
		fr.NewElement(200),
	}
	ciphertext, err := cipher.Encrypt(ad, plaintext)
	require.NoError(t, err)

	// 修改 HMAC
	ciphertext[len(ciphertext)-1] = fr.NewElement(99999)

	// 测试解密失败
	_, err = cipher.Decrypt(ad, ciphertext)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "HMAC verification failed")
}

func TestStreamCipher_Decrypt_OddLengthCiphertext(t *testing.T) {
	key := fr.NewElement(12345)
	nonce := fr.NewElement(67890)

	cipher := &circuits.StreamCipher{
		Key: [2]fr.Element{key, nonce},
	}

	ad := []fr.Element{
		fr.NewElement(10),
		fr.NewElement(20),
	}

	ciphertext := []fr.Element{
		fr.NewElement(100),
	}

	_, err := cipher.Decrypt(ad, ciphertext)
	assert.Error(t, err)
}

func TestStreamCipher_Decrypt_InvalidKey(t *testing.T) {
	key1 := fr.NewElement(12345)
	key2 := fr.NewElement(54321)
	nonce := fr.NewElement(67890)

	ad := []fr.Element{
		fr.NewElement(10),
		fr.NewElement(20),
	}

	cipher1 := &circuits.StreamCipher{Key: [2]fr.Element{key1, nonce}}
	cipher2 := &circuits.StreamCipher{Key: [2]fr.Element{key2, nonce}}

	ciphertext, err := cipher1.Encrypt(ad, []fr.Element{fr.NewElement(100), fr.NewElement(200), fr.NewElement(300), fr.NewElement(400)})
	require.NoError(t, err)

	_, err = cipher1.Decrypt(ad, ciphertext)
	require.NoError(t, err)

	_, err = cipher2.Decrypt(ad, ciphertext)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "HMAC verification failed")
}

func TestStreamCipher_DifferentKeys(t *testing.T) {
	key1 := fr.NewElement(12345)
	key2 := fr.NewElement(54321)
	nonce := fr.NewElement(67890)

	ad := []fr.Element{
		fr.NewElement(10),
		fr.NewElement(20),
	}

	cipher1 := &circuits.StreamCipher{Key: [2]fr.Element{key1, nonce}}
	cipher2 := &circuits.StreamCipher{Key: [2]fr.Element{key2, nonce}}

	plaintext := []fr.Element{
		fr.NewElement(100),
		fr.NewElement(200),
	}

	ciphertext1, err := cipher1.Encrypt(ad, plaintext)
	require.NoError(t, err)

	ciphertext2, err := cipher2.Encrypt(ad, plaintext)
	require.NoError(t, err)

	assert.NotEqual(t, ciphertext1, ciphertext2)
}
