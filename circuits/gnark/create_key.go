package circuits

import (
	"crypto/rand"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	twistededwardbn254 "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
)

type PublicKey struct {
	twistededwardbn254.PointAffine
}

func CreatePublicFromSecret(secretKey big.Int) PublicKey {
	basePoint := twistededwardbn254.GetEdwardsCurve().Base

	return PublicKey{
		PointAffine: *basePoint.ScalarMultiplication(&basePoint, &secretKey),
	}
}

func CreatePublicFromRand() (PublicKey, big.Int, error) {
	maxPrivateKey := twistededwardbn254.GetEdwardsCurve().Order
	secretKey, err := rand.Int(rand.Reader, &maxPrivateKey)
	if err != nil {
		return PublicKey{}, big.Int{}, err
	}

	return CreatePublicFromSecret(*secretKey), *secretKey, nil
}

func CreateSeedFromRand() (big.Int, error) {
	maxPrivateKey := twistededwardbn254.GetEdwardsCurve().Order
	secretKey, err := rand.Int(rand.Reader, &maxPrivateKey)
	if err != nil {
		return big.Int{}, err
	}

	return *secretKey, nil
}

func BigIntToFr(bigInt big.Int) fr.Element {
	elem := fr.NewElement(0)
	elem.SetBigInt(&bigInt)

	return elem
}
