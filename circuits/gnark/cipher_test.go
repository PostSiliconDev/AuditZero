package circuits

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStreamCipher_EncryptDecrypt(t *testing.T) {
	// 创建密钥和随机数
	key := fr.NewElement(12345)
	nonce := fr.NewElement(67890)

	cipher := &StreamCipher{
		Key:   key,
		Nonce: nonce,
	}

	// 测试数据 - 必须是偶数个元素
	plaintext := []fr.Element{
		fr.NewElement(100),
		fr.NewElement(200),
		fr.NewElement(300),
		fr.NewElement(400),
	}

	// 测试加密
	ciphertext, err := cipher.Encrypt(plaintext)
	require.NoError(t, err)
	assert.NotNil(t, ciphertext)
	assert.Equal(t, len(plaintext)+1, len(ciphertext)) // +1 for HMAC

	// 测试解密
	decrypted, err := cipher.Decrypt(ciphertext)
	require.NoError(t, err)
	assert.NotNil(t, decrypted)
	assert.Equal(t, len(plaintext), len(decrypted))

	// 验证解密结果与原文一致
	for i := 0; i < len(plaintext); i++ {
		assert.Equal(t, plaintext[i], decrypted[i])
	}
}

func TestStreamCipher_EncryptDecrypt_EmptyPlaintext(t *testing.T) {
	key := fr.NewElement(12345)
	nonce := fr.NewElement(67890)

	cipher := &StreamCipher{
		Key:   key,
		Nonce: nonce,
	}

	// 测试空明文
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

	cipher := &StreamCipher{
		Key:   key,
		Nonce: nonce,
	}

	// 测试奇数长度的明文
	plaintext := []fr.Element{
		fr.NewElement(100),
		fr.NewElement(200),
		fr.NewElement(300), // 奇数个元素
	}

	_, err := cipher.Encrypt(plaintext)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "even number of elements")
}

func TestStreamCipher_Decrypt_EmptyCiphertext(t *testing.T) {
	key := fr.NewElement(12345)
	nonce := fr.NewElement(67890)

	cipher := &StreamCipher{
		Key:   key,
		Nonce: nonce,
	}

	// 测试空密文
	_, err := cipher.Decrypt([]fr.Element{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "at least one element")
}

func TestStreamCipher_Decrypt_InvalidHMAC(t *testing.T) {
	key := fr.NewElement(12345)
	nonce := fr.NewElement(67890)

	cipher := &StreamCipher{
		Key:   key,
		Nonce: nonce,
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

	cipher := &StreamCipher{
		Key:   key,
		Nonce: nonce,
	}

	// 测试奇数长度的密文（不包括 HMAC）
	ciphertext := []fr.Element{
		fr.NewElement(100), // 奇数个元素
	}

	_, err := cipher.Decrypt(ciphertext)
	assert.Error(t, err)
}

func TestXOR(t *testing.T) {
	// 测试 XOR 函数
	a := fr.NewElement(10)        // 1010
	b := fr.NewElement(6)         // 0110
	expected := fr.NewElement(12) // (10 XOR 6)

	result := xor(a, b)
	assert.Equal(t, expected, result)

	result2 := xor(b, a)
	assert.Equal(t, expected, result2)

	zero := fr.NewElement(0)
	result3 := xor(a, zero)
	assert.Equal(t, a, result3)

	result4 := xor(a, a)
	assert.Equal(t, zero, result4)
}

func TestStreamCipher_DifferentKeys(t *testing.T) {
	key1 := fr.NewElement(12345)
	key2 := fr.NewElement(54321)
	nonce := fr.NewElement(67890)

	cipher1 := &StreamCipher{Key: key1, Nonce: nonce}
	cipher2 := &StreamCipher{Key: key2, Nonce: nonce}

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

	cipher1 := &StreamCipher{Key: key, Nonce: nonce1}
	cipher2 := &StreamCipher{Key: key, Nonce: nonce2}

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
