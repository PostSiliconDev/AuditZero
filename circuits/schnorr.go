package circuits

import (
	"fmt"
	"hide-pay/utils"

	twistededwardbn254 "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
)

type SchnorrGadget struct {
	Message   frontend.Variable    `gnark:"message"`
	Signature frontend.Variable    `gnark:"signature"`
	Random    [2]frontend.Variable `gnark:"random"`
	PublicKey [2]frontend.Variable `gnark:"publicKey"`
}

func NewSchnorrGadget(message frontend.Variable, signature frontend.Variable, random [2]frontend.Variable, publicKey [2]frontend.Variable) *SchnorrGadget {
	return &SchnorrGadget{
		Message:   message,
		Signature: signature,
		Random:    random,
		PublicKey: publicKey,
	}
}

func (gadget *SchnorrGadget) VerifySignature(api frontend.API) error {
	message, err := gadget.computeHash(api)
	if err != nil {
		return err
	}
	curve, err := twistededwards.NewEdCurve(api, twistededwardbn254.BN254)
	if err != nil {
		return err
	}
	base := twistededwards.Point{
		X: curve.Params().Base[0],
		Y: curve.Params().Base[1],
	}
	sG := curve.ScalarMul(base, gadget.Signature)

	pubKeyPoint := twistededwards.Point{
		X: gadget.PublicKey[0],
		Y: gadget.PublicKey[1],
	}
	cP := curve.ScalarMul(pubKeyPoint, message)

	// Calculate R + c * P
	rPoint := twistededwards.Point{
		X: gadget.Random[0],
		Y: gadget.Random[1],
	}
	RcP := curve.Add(rPoint, cP)

	api.AssertIsEqual(sG.X, RcP.X)
	api.AssertIsEqual(sG.Y, RcP.Y)

	return nil
}

func (gadget *SchnorrGadget) computeHash(api frontend.API) (frontend.Variable, error) {
	hasher, err := utils.NewPoseidonHasher(api)
	if err != nil {
		return nil, fmt.Errorf("failed to create poseidon hasher: %w", err)
	}

	hasher.Write(gadget.Message)
	hasher.Write(gadget.Random[0])
	hasher.Write(gadget.Random[1])
	hasher.Write(gadget.PublicKey[0])
	hasher.Write(gadget.PublicKey[1])

	return hasher.Sum(), nil
}
