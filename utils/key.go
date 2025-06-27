package utils

import (
	"math/big"

	twistededwardbn254 "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
)

func BuildPublicKey(secretKey big.Int) twistededwardbn254.PointAffine {
	basePoint := twistededwardbn254.GetEdwardsCurve().Base

	return *basePoint.ScalarMultiplication(&basePoint, &secretKey)
}
