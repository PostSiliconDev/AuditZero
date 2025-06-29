package builder

import (
	"hide-pay/circuits"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	twistededwardbn254 "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"github.com/consensys/gnark/frontend"
)

type UTXOResult struct {
	Nullifiers  []fr.Element
	Commitments []UTXOCommitment
	AllAsset    []fr.Element
	Root        fr.Element
}

type UTXOCommitment struct {
	Commitment               fr.Element
	OwnerMemo                [3]fr.Element
	OwnerHMAC                fr.Element
	OwnerEphemeralPublickKey twistededwardbn254.PointAffine
	AuditMemo                [3]fr.Element
	AuditHMAC                fr.Element
	AuditEphemeralPublickKey twistededwardbn254.PointAffine
}

func (result *UTXOResult) ToGadget() *circuits.UTXOResultGadget {
	nullifiers := make([]frontend.Variable, len(result.Nullifiers))
	commitments := make([]frontend.Variable, len(result.Commitments))
	ownerMemoHashes := make([]frontend.Variable, len(result.Commitments))
	auditMemoHashes := make([]frontend.Variable, len(result.Commitments))
	allAsset := make([]frontend.Variable, len(result.AllAsset))

	for i := range result.Nullifiers {
		nullifiers[i] = result.Nullifiers[i]
	}

	for i := range result.Commitments {
		commitments[i] = result.Commitments[i].Commitment
		ownerMemoHashes[i] = result.Commitments[i].OwnerHMAC
		auditMemoHashes[i] = result.Commitments[i].AuditHMAC
	}

	for i := range result.AllAsset {
		allAsset[i] = result.AllAsset[i]
	}

	return &circuits.UTXOResultGadget{
		Nullifiers:      nullifiers,
		Commitments:     commitments,
		OwnerMemoHashes: ownerMemoHashes,
		AuditMemoHashes: auditMemoHashes,
	}
}
