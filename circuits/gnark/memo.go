package circuits

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	twistededwardbn254 "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"github.com/consensys/gnark/frontend"
)

type MemoGadget struct {
	EphemeralSecretKey frontend.Variable    `gnark:"ephemeralSecretKey"`
	ReceiverPublicKey  [2]frontend.Variable `gnark:"receiverPublicKey"`
}

func (gadget *MemoGadget) Generate(api frontend.API, output CommitmentGadget) (frontend.Variable, error) {
	ecdh := NewECDHGadget(api)

	sharedKey, err := ecdh.Compute(gadget.ReceiverPublicKey, gadget.EphemeralSecretKey)
	if err != nil {
		return nil, fmt.Errorf("failed to compute shared key: %w", err)
	}

	streamCipher := NewStreamCipherGadget(api)

	plaintext := []frontend.Variable{
		output.Asset,
		output.Amount,
		output.Blinding,
		0,
	}

	ciphertext, err := streamCipher.Encrypt(sharedKey, plaintext)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt: %w", err)
	}

	return ciphertext[len(ciphertext)-1], nil
}

type Memo struct {
	EphemeralSecretKey big.Int
	ReceiverPublicKey  twistededwardbn254.PointAffine
}

func (memo *Memo) Encrypt(commitment Commitment) ([]fr.Element, error) {
	ecdh := ECDH{
		PublicKey: memo.ReceiverPublicKey,
		SecretKey: memo.EphemeralSecretKey,
	}

	sharedKey := ecdh.Compute()

	streamCipher := StreamCipher{
		Key: [2]fr.Element{sharedKey.X, sharedKey.Y},
	}

	plaintext := []fr.Element{
		commitment.Asset,
		commitment.Amount,
		commitment.Blinding,
		fr.NewElement(0),
	}

	return streamCipher.Encrypt(plaintext)
}

func (memo *Memo) Decrypt(ciphertext []fr.Element) (*Commitment, error) {
	ecdh := ECDH{
		PublicKey: memo.ReceiverPublicKey,
		SecretKey: memo.EphemeralSecretKey,
	}

	sharedKey := ecdh.Compute()

	streamCipher := StreamCipher{
		Key: [2]fr.Element{sharedKey.X, sharedKey.Y},
	}

	plaintext, err := streamCipher.Decrypt(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return &Commitment{
		Asset:    plaintext[0],
		Amount:   plaintext[1],
		Blinding: plaintext[2],
	}, nil
}
