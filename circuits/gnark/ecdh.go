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
	api frontend.API
}

func NewECDHGadget(api frontend.API) *ECDHGadget {
	return &ECDHGadget{
		api: api,
	}
}

func (gadget *ECDHGadget) Compute(publicKey [2]frontend.Variable, secretKey frontend.Variable) ([2]frontend.Variable, error) {
	te, err := twistededwards.NewEdCurve(gadget.api, twistededwardscrypto.BN254)
	if err != nil {
		return [2]frontend.Variable{}, fmt.Errorf("failed to create twistededwards curve: %w", err)
	}

	params := te.Params()

	base_point := twistededwards.Point{
		X: params.Base[0],
		Y: params.Base[1],
	}

	sharedKey := te.ScalarMul(base_point, secretKey)

	return [2]frontend.Variable{sharedKey.X, sharedKey.Y}, nil
}

type ECDHCircuit struct {
	PublicKey [2]frontend.Variable
	SecretKey frontend.Variable
	SharedKey [2]frontend.Variable `gnark:",public"`
}

func NewECDHCircuit() *ECDHCircuit {
	return &ECDHCircuit{}
}

func (circuit *ECDHCircuit) Define(api frontend.API) error {
	gadget := NewECDHGadget(api)

	sharedKey, err := gadget.Compute(circuit.PublicKey, circuit.SecretKey)
	if err != nil {
		return fmt.Errorf("failed to compute shared key: %w", err)
	}

	api.AssertIsEqual(circuit.SharedKey[0], sharedKey[0])
	api.AssertIsEqual(circuit.SharedKey[1], sharedKey[1])

	return nil
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
	base_point := twistededwardbn254.GetEdwardsCurve().Base

	shared_key := base_point.ScalarMultiplication(&base_point, &ecdh.SecretKey)

	return *shared_key
}

func (ecdh *ECDH) ToWitness() *ECDHCircuit {
	shared_key := ecdh.Compute()

	return &ECDHCircuit{
		PublicKey: [2]frontend.Variable{ecdh.PublicKey.X, ecdh.PublicKey.Y},
		SecretKey: ecdh.SecretKey,
		SharedKey: [2]frontend.Variable{shared_key.X, shared_key.Y},
	}
}
