package circuits

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	twistededwardbn254 "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	twistededwardscrypto "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
)

type ECDHCircuit struct {
	PublicKeyX frontend.Variable `gnark:"publicKeyX"`
	PublicKeyY frontend.Variable `gnark:"publicKeyY"`
	SecretKey  frontend.Variable `gnark:"secretKey"`
	SharedKeyX frontend.Variable `gnark:"sharedKeyX,public"`
	SharedKeyY frontend.Variable `gnark:"sharedKeyY,public"`
}

func NewECDHCircuit() *ECDHCircuit {
	return &ECDHCircuit{}
}

func (circuit *ECDHCircuit) Define(api frontend.API) error {
	te, err := twistededwards.NewEdCurve(api, twistededwardscrypto.BN254)
	if err != nil {
		return fmt.Errorf("failed to create twistededwards curve: %w", err)
	}

	params := te.Params()

	base_point := twistededwards.Point{
		X: params.Base[0],
		Y: params.Base[1],
	}

	sharedKey := te.ScalarMul(base_point, circuit.SecretKey)
	api.AssertIsEqual(circuit.SharedKeyX, sharedKey.X)
	api.AssertIsEqual(circuit.SharedKeyY, sharedKey.Y)

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

func (ecdh *ECDH) Compute() (fr.Element, fr.Element) {
	base_point := twistededwardbn254.GetEdwardsCurve().Base

	shared_key := base_point.ScalarMultiplication(&base_point, &ecdh.SecretKey)

	return shared_key.X, shared_key.Y
}

func (ecdh *ECDH) ToWitness() *ECDHCircuit {
	shared_key_x, shared_key_y := ecdh.Compute()

	return &ECDHCircuit{
		PublicKeyX: ecdh.PublicKey.X,
		PublicKeyY: ecdh.PublicKey.Y,
		SecretKey:  ecdh.SecretKey,
		SharedKeyX: shared_key_x,
		SharedKeyY: shared_key_y,
	}
}
