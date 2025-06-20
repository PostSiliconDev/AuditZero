package circuits_test

import (
	circuits "hide-pay/circuits/gnark"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStreamCipher_EncryptDecrypt(t *testing.T) {
	key := fr.NewElement(12345)
	nonce := fr.NewElement(67890)

	cipher := &circuits.StreamCipher{
		Key: [2]fr.Element{key, nonce},
	}

	plaintext := []fr.Element{
		fr.NewElement(100),
		fr.NewElement(200),
		fr.NewElement(300),
		fr.NewElement(400),
	}

	ciphertext, err := cipher.Encrypt(plaintext)
	require.NoError(t, err)
	assert.NotNil(t, ciphertext)
	assert.Equal(t, len(plaintext)+1, len(ciphertext)) // +1 for HMAC

	decrypted, err := cipher.Decrypt(ciphertext)
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

	plaintext := []fr.Element{}

	ciphertext, err := cipher.Encrypt(plaintext)
	require.NoError(t, err)
	assert.Equal(t, 1, len(ciphertext)) // 只有 HMAC

	decrypted, err := cipher.Decrypt(ciphertext)
	require.NoError(t, err)
	assert.Equal(t, 0, len(decrypted))
}

func TestStreamCipher_Encrypt_OddLengthError(t *testing.T) {
	key := fr.NewElement(12345)
	nonce := fr.NewElement(67890)

	cipher := &circuits.StreamCipher{
		Key: [2]fr.Element{key, nonce},
	}

	plaintext := []fr.Element{
		fr.NewElement(100),
		fr.NewElement(200),
		fr.NewElement(300),
	}

	_, err := cipher.Encrypt(plaintext)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "even number of elements")
}

func TestStreamCipher_Decrypt_EmptyCiphertext(t *testing.T) {
	key := fr.NewElement(12345)
	nonce := fr.NewElement(67890)

	cipher := &circuits.StreamCipher{
		Key: [2]fr.Element{key, nonce},
	}

	// 测试空密文
	_, err := cipher.Decrypt([]fr.Element{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "at least one element")
}

func TestStreamCipher_Decrypt_InvalidHMAC(t *testing.T) {
	key := fr.NewElement(12345)
	nonce := fr.NewElement(67890)

	cipher := &circuits.StreamCipher{
		Key: [2]fr.Element{key, nonce},
	}

	// 创建有效的密文
	plaintext := []fr.Element{
		fr.NewElement(100),
		fr.NewElement(200),
	}
	ciphertext, err := cipher.Encrypt(plaintext)
	require.NoError(t, err)

	// 修改 HMAC
	ciphertext[len(ciphertext)-1] = fr.NewElement(99999)

	// 测试解密失败
	_, err = cipher.Decrypt(ciphertext)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "HMAC verification failed")
}

func TestStreamCipher_Decrypt_OddLengthCiphertext(t *testing.T) {
	key := fr.NewElement(12345)
	nonce := fr.NewElement(67890)

	cipher := &circuits.StreamCipher{
		Key: [2]fr.Element{key, nonce},
	}

	ciphertext := []fr.Element{
		fr.NewElement(100),
	}

	_, err := cipher.Decrypt(ciphertext)
	assert.Error(t, err)
}

func TestStreamCipher_DifferentKeys(t *testing.T) {
	key1 := fr.NewElement(12345)
	key2 := fr.NewElement(54321)
	nonce := fr.NewElement(67890)

	cipher1 := &circuits.StreamCipher{Key: [2]fr.Element{key1, nonce}}
	cipher2 := &circuits.StreamCipher{Key: [2]fr.Element{key2, nonce}}

	plaintext := []fr.Element{
		fr.NewElement(100),
		fr.NewElement(200),
	}

	ciphertext1, err := cipher1.Encrypt(plaintext)
	require.NoError(t, err)

	ciphertext2, err := cipher2.Encrypt(plaintext)
	require.NoError(t, err)

	assert.NotEqual(t, ciphertext1, ciphertext2)
}

func TestStreamCipher_DifferentNonces(t *testing.T) {
	key := fr.NewElement(12345)
	nonce1 := fr.NewElement(67890)
	nonce2 := fr.NewElement(98765)

	cipher1 := &circuits.StreamCipher{Key: [2]fr.Element{key, nonce1}}
	cipher2 := &circuits.StreamCipher{Key: [2]fr.Element{key, nonce2}}

	plaintext := []fr.Element{
		fr.NewElement(100),
		fr.NewElement(200),
	}

	ciphertext1, err := cipher1.Encrypt(plaintext)
	require.NoError(t, err)

	ciphertext2, err := cipher2.Encrypt(plaintext)
	require.NoError(t, err)

	assert.NotEqual(t, ciphertext1, ciphertext2)
}

func TestStreamCipher_Circuit(t *testing.T) {

	key := fr.NewElement(12345)
	nonce := fr.NewElement(67890)

	cipher := &circuits.StreamCipher{
		Key: [2]fr.Element{key, nonce},
	}

	plaintext := []fr.Element{
		fr.NewElement(100),
		fr.NewElement(200),
		fr.NewElement(300),
		fr.NewElement(400),
	}

	ciphertext, err := cipher.Encrypt(plaintext)
	require.NoError(t, err)
	assert.NotNil(t, ciphertext)
	assert.Equal(t, len(plaintext)+1, len(ciphertext))

	assert := test.NewAssert(t)

	circuit := circuits.NewStreamCipherCircuit(4)

	options := test.WithCurves(ecc.BN254)

	witness := &circuits.StreamCipherCircuit{
		Key: [2]frontend.Variable{key[0], key[1]},
		Plaintext: []frontend.Variable{
			plaintext[0],
			plaintext[1],
			plaintext[2],
			plaintext[3],
		},
		Ciphertext: []frontend.Variable{
			ciphertext[0],
			ciphertext[1],
			ciphertext[2],
			ciphertext[3],
			ciphertext[4],
		},
	}

	assert.ProverSucceeded(circuit, witness, options)
}
