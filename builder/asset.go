package builder

import (
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon2"
)

type Asset struct {
	AuditPublicKey PublicKey
	FreezeAddr     Address
	Random         fr.Element
}

func (a *Asset) ComputeAssetId() AssetId {
	hasher := poseidon2.NewMerkleDamgardHasher()

	auditPublicKeyXBytes := a.AuditPublicKey.PublicKey.X.Bytes()
	auditPublicKeyYBytes := a.AuditPublicKey.PublicKey.Y.Bytes()
	freezeAddrBytes := a.FreezeAddr.Bytes()
	randomBytes := a.Random.Bytes()

	hasher.Write(auditPublicKeyXBytes[:])
	hasher.Write(auditPublicKeyYBytes[:])
	hasher.Write(freezeAddrBytes[:])

	assetIdBytes := hasher.Sum(randomBytes[:])

	var assetId fr.Element
	assetId.SetBytes(assetIdBytes)

	return AssetId{
		AssetId: assetId,
	}
}

type AssetId struct {
	AssetId fr.Element
}

func (a *AssetId) Bytes() [32]byte {
	return a.AssetId.Bytes()
}
