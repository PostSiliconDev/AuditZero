package builder

import (
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon2"
)

type OpenedCommitment struct {
	AssetId
	Amount     fr.Element
	FreezeFlag bool
	Random     fr.Element
	OwnerKey   PrivateKey
	SenderKey  PrivateKey
	ExtraData  []fr.Element
}

func (o *OpenedCommitment) GetCommitment() Commitment {
	extraHasher := poseidon2.NewMerkleDamgardHasher()

	for i := range o.ExtraData {
		extraDataBytes := o.ExtraData[i].Bytes()
		extraHasher.Write(extraDataBytes[:])
	}

	extraHashBytes := extraHasher.Sum(nil)
	var extraHash fr.Element
	extraHash.SetBytes(extraHashBytes)

	commitment := Commitment{
		AssetId:    o.AssetId,
		Amount:     o.Amount,
		FreezeFlag: o.FreezeFlag,
		Random:     o.Random,
		ExtraHash:  extraHash,
		OwnerAddr:  o.OwnerKey.Address(),
		SpentAddr:  o.SenderKey.Address(),
	}

	return commitment
}

func (o *OpenedCommitment) GetNullifier() Nullifier {
	commitment := o.GetCommitment()
	commitmentHash := commitment.ComputeCommitmentHash()
	nullifier := commitmentHash.GetNullifier(o.OwnerKey)
	return nullifier
}
