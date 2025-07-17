package builder

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon2"
	twistededwardbn254 "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
)

type Signature struct {
	R twistededwardbn254.PointAffine
	S fr.Element
}

type Keypair struct {
	PublicKey twistededwardbn254.PointAffine
	SecretKey fr.Element
}

func GenerateKeypair() (*Keypair, error) {
	secretKey := fr.Element{}
	_, err := secretKey.SetRandom()
	if err != nil {
		return nil, err
	}

	kp := &Keypair{
		SecretKey: secretKey,
		PublicKey: twistededwardbn254.PointAffine{},
	}

	base := twistededwardbn254.GetEdwardsCurve().Base
	secretKeyBigInt := big.NewInt(0)
	kp.SecretKey.BigInt(secretKeyBigInt)

	kp.PublicKey = *kp.PublicKey.ScalarMultiplication(&base, secretKeyBigInt)

	return kp, nil
}

func (kp *Keypair) Sign(messageHash fr.Element) (*Signature, error) {
	random := fr.Element{}
	_, err := random.SetRandom()
	if err != nil {
		return nil, err
	}

	randomBigInt := big.NewInt(0)
	random.BigInt(randomBigInt)

	if random.IsZero() {
		random.SetOne()
	}

	var R twistededwardbn254.PointAffine
	base := twistededwardbn254.GetEdwardsCurve().Base
	R.ScalarMultiplication(&base, randomBigInt)

	c := computeHash(messageHash, &R, &kp.PublicKey)

	cx := c.Mul(&kp.SecretKey, &c)
	s := c.Add(&random, cx)

	signature := &Signature{
		R: R,
		S: *s,
	}

	return signature, nil
}

func Verify(messageHash fr.Element, signature *Signature, publicKey *twistededwardbn254.PointAffine) bool {
	c := computeHash(messageHash, &signature.R, publicKey)

	var sG twistededwardbn254.PointAffine
	base := twistededwardbn254.GetEdwardsCurve().Base
	sG.ScalarMultiplication(&base, signature.S.BigInt(nil))

	var cP twistededwardbn254.PointAffine
	cP.ScalarMultiplication(publicKey, c.BigInt(nil))

	var RcP twistededwardbn254.PointAffine
	RcP.Add(&signature.R, &cP)

	return sG.Equal(&RcP)
}

func computeHash(message fr.Element, R *twistededwardbn254.PointAffine, P *twistededwardbn254.PointAffine) fr.Element {
	hasher := poseidon2.NewMerkleDamgardHasher()

	messageBytes := message.Bytes()
	rXBytes := R.X.Bytes()
	rYBytes := R.Y.Bytes()
	pXBytes := P.X.Bytes()
	pYBytes := P.Y.Bytes()

	hasher.Write(messageBytes[:])
	hasher.Write(rXBytes[:])
	hasher.Write(rYBytes[:])
	hasher.Write(pXBytes[:])
	hasher.Write(pYBytes[:])

	hashBytes := hasher.Sum(nil)

	hash := fr.Element{}
	hash.SetBytes(hashBytes)

	return hash
}
