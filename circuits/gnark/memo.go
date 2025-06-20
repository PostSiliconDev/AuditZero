package circuits

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	twistededwardbn254 "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	twistededwardcrypto "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
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
	}

	curve, err := twistededwards.NewEdCurve(api, twistededwardcrypto.BN254)
	if err != nil {
		return nil, fmt.Errorf("failed to create curve: %w", err)
	}

	basePointOriginal := curve.Params().Base
	basePoint := twistededwards.Point{
		X: basePointOriginal[0],
		Y: basePointOriginal[1],
	}

	ephemeralPublicKey := curve.ScalarMul(basePoint, gadget.EphemeralSecretKey)

	ad := []frontend.Variable{
		ephemeralPublicKey.X,
		ephemeralPublicKey.Y,
	}

	ciphertext, err := streamCipher.Encrypt(sharedKey, ad, plaintext)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt: %w", err)
	}

	return ciphertext, nil
}

type Memo struct {
	SecretKey big.Int
	PublicKey twistededwardbn254.PointAffine
}

func (memo *Memo) Encrypt(commitment Commitment) (*twistededwardbn254.PointAffine, []fr.Element, error) {
	ecdh := ECDH{
		PublicKey: memo.PublicKey,
		SecretKey: memo.SecretKey,
	}

	sharedKey := ecdh.Compute()

	streamCipher := StreamCipher{
		Key: [2]fr.Element{sharedKey.X, sharedKey.Y},
	}

	basePoint := twistededwardbn254.GetEdwardsCurve().Base
	ephemeralPublicKey := basePoint.ScalarMultiplication(&basePoint, &memo.SecretKey)

	ad := []fr.Element{
		ephemeralPublicKey.X,
		ephemeralPublicKey.Y,
	}

	plaintext := []fr.Element{
		commitment.Asset,
		commitment.Amount,
		commitment.Blinding,
	}

	ciphertext, err := streamCipher.Encrypt(ad, plaintext)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encrypt: %w", err)
	}

	return ephemeralPublicKey, ciphertext, nil
}

func (memo *Memo) Decrypt(ciphertext []fr.Element) (*Commitment, error) {
	ecdh := ECDH{
		PublicKey: memo.PublicKey,
		SecretKey: memo.SecretKey,
	}

	sharedKey := ecdh.Compute()

	streamCipher := StreamCipher{
		Key: [2]fr.Element{sharedKey.X, sharedKey.Y},
	}

	ad := []fr.Element{
		memo.PublicKey.X,
		memo.PublicKey.Y,
	}

	plaintext, err := streamCipher.Decrypt(ad, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return &Commitment{
		Asset:    plaintext[0],
		Amount:   plaintext[1],
		Blinding: plaintext[2],
	}, nil
}
