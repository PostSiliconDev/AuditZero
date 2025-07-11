package builder

import (
	"fmt"
	"hide-pay/circuits"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon2"
	twistededwardbn254 "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
)

type Commitment struct {
	Asset         fr.Element
	Amount        fr.Element
	OwnerPubKey   twistededwardbn254.PointAffine
	SpentAddress  fr.Element
	ViewPubKey    twistededwardbn254.PointAffine
	AuditPubKey   twistededwardbn254.PointAffine
	FreezeAddress fr.Element
	FreezeFlag    fr.Element
	Blinding      fr.Element
}

func (commitment *Commitment) ToGadget() *circuits.CommitmentGadget {
	return &circuits.CommitmentGadget{
		Asset:    commitment.Asset,
		Amount:   commitment.Amount,
		Blinding: commitment.Blinding,
	}
}

func (commitment *Commitment) String() string {
	return fmt.Sprintf("Commitment(Asset: %s, Amount: %s, Blinding: %s,)", commitment.Asset.Text(10), commitment.Amount.Text(10), commitment.Blinding.Text(10))
}

func (commitment *Commitment) Compute() fr.Element {
	hasher := poseidon2.NewMerkleDamgardHasher()

	assetBytes := commitment.Asset.Bytes()
	amountBytes := commitment.Amount.Bytes()
	ownerPubKeyXBytes := commitment.OwnerPubKey.X.Bytes()
	ownerPubKeyYBytes := commitment.OwnerPubKey.Y.Bytes()
	spentAddressBytes := commitment.SpentAddress.Bytes()
	viewPubKeyXBytes := commitment.ViewPubKey.X.Bytes()
	viewPubKeyYBytes := commitment.ViewPubKey.Y.Bytes()
	auditPubKeyXBytes := commitment.AuditPubKey.X.Bytes()
	auditPubKeyYBytes := commitment.AuditPubKey.Y.Bytes()
	freezeAddressBytes := commitment.FreezeAddress.Bytes()
	freezeFlagBytes := commitment.FreezeFlag.Bytes()
	blindingBytes := commitment.Blinding.Bytes()

	hasher.Write(assetBytes[:])
	hasher.Write(amountBytes[:])
	hasher.Write(ownerPubKeyXBytes[:])
	hasher.Write(ownerPubKeyYBytes[:])
	hasher.Write(spentAddressBytes[:])
	hasher.Write(viewPubKeyXBytes[:])
	hasher.Write(viewPubKeyYBytes[:])
	hasher.Write(auditPubKeyXBytes[:])
	hasher.Write(auditPubKeyYBytes[:])
	hasher.Write(freezeAddressBytes[:])
	hasher.Write(freezeFlagBytes[:])

	resBytes := hasher.Sum(blindingBytes[:])

	res := fr.Element{}
	res.Unmarshal(resBytes)

	return res
}
