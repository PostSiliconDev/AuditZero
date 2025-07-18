package builder

import (
	"fmt"
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

	base := twistededwardbn254.GetEdwardsCurve().Base
	secretKeyBigInt := big.NewInt(0)
	secretKey.BigInt(secretKeyBigInt)

	var publicKey twistededwardbn254.PointAffine
	publicKey.ScalarMultiplication(&base, secretKeyBigInt)

	return &Keypair{
		SecretKey: secretKey,
		PublicKey: publicKey,
	}, nil
}

func GenerateKeypairWithSeed(privateKey fr.Element) (*Keypair, error) {
	base := twistededwardbn254.GetEdwardsCurve().Base
	secretKeyBigInt := big.NewInt(0)
	privateKey.BigInt(secretKeyBigInt)

	var publicKey twistededwardbn254.PointAffine
	publicKey.ScalarMultiplication(&base, secretKeyBigInt)

	return &Keypair{
		SecretKey: privateKey,
		PublicKey: publicKey,
	}, nil
}

func (kp *Keypair) Sign(random fr.Element, messageHash fr.Element) *Signature {
	var randomBigInt big.Int
	random.BigInt(&randomBigInt)

	if random.IsZero() {
		random.SetOne()
	}

	var R twistededwardbn254.PointAffine
	base := twistededwardbn254.GetEdwardsCurve().Base
	R.ScalarMultiplication(&base, &randomBigInt)

	c := computeHash(messageHash, &R, &kp.PublicKey)

	var cx fr.Element
	cx.Mul(&kp.SecretKey, &c)

	var s fr.Element
	s.Add(&random, &cx)

	signature := &Signature{
		R: R,
		S: s,
	}

	return signature
}

func Verify(messageHash fr.Element, signature *Signature, publicKey *twistededwardbn254.PointAffine) bool {
	c := computeHash(messageHash, &signature.R, publicKey)

	var sG twistededwardbn254.PointAffine
	base := twistededwardbn254.GetEdwardsCurve().Base
	sBigInt := big.NewInt(0)
	signature.S.BigInt(sBigInt)
	sG.ScalarMultiplication(&base, sBigInt)

	var cP twistededwardbn254.PointAffine
	cPBigInt := big.NewInt(0)
	c.BigInt(cPBigInt)
	cP.ScalarMultiplication(publicKey, cPBigInt)

	fmt.Println("sG", sG.X.Text(10), sG.Y.Text(10))

	var RcP twistededwardbn254.PointAffine
	RcP.Add(&signature.R, &cP)

	fmt.Println("RcP", RcP.X.Text(10), RcP.Y.Text(10))
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
