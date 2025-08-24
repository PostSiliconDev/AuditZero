package builder

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon2"
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
)

type PrivateKey struct {
	PrivateKey fr.Element
}

func (k *PrivateKey) Bytes() [32]byte {
	return k.PrivateKey.Bytes()
}

func (k *PrivateKey) PublicKey() PublicKey {
	base := twistededwards.GetEdwardsCurve().Base

	var privateKeyBig big.Int
	k.PrivateKey.BigInt(&privateKeyBig)

	var publicKey twistededwards.PointAffine
	publicKey.ScalarMultiplication(&base, &privateKeyBig)

	return PublicKey{
		PublicKey: publicKey,
	}
}

func (k *PrivateKey) Address() Address {
	hasher := poseidon2.NewMerkleDamgardHasher()

	privateKeyBytes := k.PrivateKey.Bytes()

	hasher.Write(privateKeyBytes[:])

	var address fr.Element
	address.SetBytes(hasher.Sum(nil))

	return Address{
		Address: address,
	}
}

type PublicKey struct {
	PublicKey twistededwards.PointAffine
}

type Address struct {
	Address fr.Element
}

func (a *Address) Bytes() [32]byte {
	return a.Address.Bytes()
}

type SharedKey struct {
	SharedKey twistededwards.PointAffine
}

func NewSharedKey(senderPrivateKey PrivateKey, receiverPublicKey PublicKey) SharedKey {
	sharedKey := twistededwards.PointAffine{}

	var privateKeyBig big.Int
	senderPrivateKey.PrivateKey.BigInt(&privateKeyBig)

	sharedKey.ScalarMultiplication(&receiverPublicKey.PublicKey, &privateKeyBig)

	return SharedKey{
		SharedKey: sharedKey,
	}
}
