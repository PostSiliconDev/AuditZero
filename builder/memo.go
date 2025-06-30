package builder

import (
	"fmt"
	"hide-pay/circuits"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	twistededwardbn254 "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"github.com/consensys/gnark/frontend"
)

type Memo struct {
	SecretKey big.Int
	PublicKey twistededwardbn254.PointAffine
}

func (memo *Memo) ToGadget() *circuits.MemoGadget {
	return &circuits.MemoGadget{
		EphemeralSecretKey: memo.SecretKey,
		ReceiverPublicKey:  [2]frontend.Variable{memo.PublicKey.X, memo.PublicKey.Y},
	}
}

func (memo *Memo) Encrypt(commitment circuits.Commitment) (*twistededwardbn254.PointAffine, []fr.Element, error) {
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

func (memo *Memo) Decrypt(ciphertext []fr.Element) (*circuits.Commitment, error) {
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

	return &circuits.Commitment{
		Asset:    plaintext[0],
		Amount:   plaintext[1],
		Blinding: plaintext[2],
	}, nil
}
