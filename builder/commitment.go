package builder

import (
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon2"
)

type Commitment struct {
	AssetId
	Amount     fr.Element
	OwnerAddr  Address
	SpentAddr  Address
	FreezeFlag bool
	Random     fr.Element
	ExtraHash  fr.Element
}

func (c *Commitment) ComputeCommitmentHash() CommitmentHash {
	hasher := poseidon2.NewMerkleDamgardHasher()

	freezeFlag := fr.Element{}
	if c.FreezeFlag {
		freezeFlag.SetOne()
	} else {
		freezeFlag.SetZero()
	}

	assetIdBytes := c.AssetId.Bytes()
	amountBytes := c.Amount.Bytes()
	ownerAddrBytes := c.OwnerAddr.Bytes()
	spentAddrBytes := c.SpentAddr.Bytes()
	freezeFlagBytes := freezeFlag.Bytes()
	randomBytes := c.Random.Bytes()
	extraHashBytes := c.ExtraHash.Bytes()

	hasher.Write(assetIdBytes[:])
	hasher.Write(amountBytes[:])
	hasher.Write(ownerAddrBytes[:])
	hasher.Write(spentAddrBytes[:])
	hasher.Write(freezeFlagBytes[:])
	hasher.Write(randomBytes[:])
	commitmentHashBytes := hasher.Sum(extraHashBytes[:])

	var commitmentHash fr.Element
	commitmentHash.SetBytes(commitmentHashBytes)

	return CommitmentHash{
		CommitmentHash: commitmentHash,
	}
}

type CommitmentHash struct {
	CommitmentHash fr.Element
}

func (c *CommitmentHash) Bytes() [32]byte {
	return c.CommitmentHash.Bytes()
}

func (c *CommitmentHash) GetNullifier(ownerPrivateKey PrivateKey) Nullifier {
	nullifierHasher := poseidon2.NewMerkleDamgardHasher()

	commitmentHashBytes := c.Bytes()
	privateKeyBytes := ownerPrivateKey.Bytes()

	nullifierHasher.Write(commitmentHashBytes[:])
	nullifierBytes := nullifierHasher.Sum(privateKeyBytes[:])

	var nullifier fr.Element
	nullifier.SetBytes(nullifierBytes)

	return Nullifier{
		Nullifier: nullifier,
	}
}

type Nullifier struct {
	Nullifier fr.Element
}
