package circuits

import (
	"fmt"

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
