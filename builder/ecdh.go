package builder

import (
	"hide-pay/circuits"
	"math/big"

	twistededwardbn254 "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"github.com/consensys/gnark/frontend"
)

type ECDH struct {
	PublicKey twistededwardbn254.PointAffine
	SecretKey big.Int
}

func NewECDH(receiverSecretKey big.Int, senderSecretKey big.Int) *ECDH {
	base_point := twistededwardbn254.GetEdwardsCurve().Base

	senderPublicKey := base_point.ScalarMultiplication(&base_point, &senderSecretKey)

	return &ECDH{
		PublicKey: *senderPublicKey,
		SecretKey: receiverSecretKey,
	}
}

func (ecdh *ECDH) Compute() twistededwardbn254.PointAffine {
	sharedKey := twistededwardbn254.PointAffine{}
	sharedKey.ScalarMultiplication(&ecdh.PublicKey, &ecdh.SecretKey)

	return sharedKey
}

func (ecdh *ECDH) ToGadget() *circuits.ECDHGadget {
	return &circuits.ECDHGadget{
		PublicKey: [2]frontend.Variable{ecdh.PublicKey.X, ecdh.PublicKey.Y},
		SecretKey: ecdh.SecretKey,
	}
}
