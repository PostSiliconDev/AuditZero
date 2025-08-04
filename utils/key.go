package utils

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	poseidonbn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon2"
	twistededwardbn254 "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
)

func BuildPublicKey(secretKey big.Int) twistededwardbn254.PointAffine {
	basePoint := twistededwardbn254.GetEdwardsCurve().Base

	return *basePoint.ScalarMultiplication(&basePoint, &secretKey)
}

func BuildAddress(secretKey big.Int) fr.Element {
	hasher := poseidonbn254.NewMerkleDamgardHasher()

	hasher.Write(secretKey.Bytes())
	hash := hasher.Sum(nil)

	hashElement := fr.NewElement(0)
	hashElement.SetBytes(hash)

	return hashElement
}
