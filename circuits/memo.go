package circuits

import (
	"fmt"

	twistededwardcrypto "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
)

type MemoGadget struct {
	EphemeralSecretKey frontend.Variable    `gnark:"ephemeralSecretKey"`
	ReceiverPublicKey  [2]frontend.Variable `gnark:"receiverPublicKey"`
}

func (gadget *MemoGadget) Generate(api frontend.API, output CommitmentGadget) (frontend.Variable, error) {
	ecdh := ECDHGadget{
		PublicKey: gadget.ReceiverPublicKey,
		SecretKey: gadget.EphemeralSecretKey,
	}

	sharedKey, err := ecdh.Compute(api)
	if err != nil {
		return nil, fmt.Errorf("failed to compute shared key: %w", err)
	}

	streamCipher := StreamCipherGadget{
		Key: sharedKey,
	}

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

	ciphertext, err := streamCipher.Encrypt(api, ad, plaintext)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt: %w", err)
	}

	return ciphertext, nil
}
