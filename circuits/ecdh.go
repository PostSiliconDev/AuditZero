package circuits

import (
	"fmt"
	"math/big"

	twistededwardbn254 "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	twistededwardscrypto "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
)

type ECDHGadget struct {
	PublicKey [2]frontend.Variable
	SecretKey frontend.Variable
}

func (gadget *ECDHGadget) Compute(api frontend.API) ([2]frontend.Variable, error) {
	te, err := twistededwards.NewEdCurve(api, twistededwardscrypto.BN254)
	if err != nil {
		return [2]frontend.Variable{}, fmt.Errorf("failed to create twistededwards curve: %w", err)
	}

	publicPoint := twistededwards.Point{
		X: gadget.PublicKey[0],
		Y: gadget.PublicKey[1],
	}

	sharedKey := te.ScalarMul(publicPoint, gadget.SecretKey)

	return [2]frontend.Variable{sharedKey.X, sharedKey.Y}, nil
}

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

func (ecdh *ECDH) ToGadget() *ECDHGadget {
	return &ECDHGadget{
		PublicKey: [2]frontend.Variable{ecdh.PublicKey.X, ecdh.PublicKey.Y},
		SecretKey: ecdh.SecretKey,
	}
}
