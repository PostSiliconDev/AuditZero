package builder

import (
	"fmt"
	"hide-pay/circuits"
	"hide-pay/utils"
	"math/big"
	"math/rand"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon2"
	twistededwardbn254 "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"github.com/consensys/gnark/frontend"
)

type Commitment struct {
	Asset       fr.Element
	Amount      fr.Element
	OwnerPubKey twistededwardbn254.PointAffine
	SpentKey    fr.Element
	// SpentAddress fr.Element
	SpentSecKey fr.Element
	ViewPubKey  twistededwardbn254.PointAffine
	AuditPubKey twistededwardbn254.PointAffine
	FreezeFlag  fr.Element
	Blinding    fr.Element
}

func (commitment *Commitment) ToGadget() *circuits.CommitmentGadget {
	return &circuits.CommitmentGadget{
		Asset:       commitment.Asset,
		Amount:      commitment.Amount,
		OwnerPubKey: [2]frontend.Variable{commitment.OwnerPubKey.X, commitment.OwnerPubKey.Y},
		SpentSecKey: commitment.SpentSecKey,
		ViewPubKey:  [2]frontend.Variable{commitment.ViewPubKey.X, commitment.ViewPubKey.Y},
		AuditPubKey: [2]frontend.Variable{commitment.AuditPubKey.X, commitment.AuditPubKey.Y},
		FreezeFlag:  commitment.FreezeFlag,
		Blinding:    commitment.Blinding,
	}
}

func formatPoint(point twistededwardbn254.PointAffine) string {
	return fmt.Sprintf("(%s, %s)", point.X.Text(10), point.Y.Text(10))
}

func (commitment *Commitment) String() string {
	assetStr := fmt.Sprintf("Asset: %s", commitment.Asset.Text(10))
	amountStr := fmt.Sprintf("Amount: %s", commitment.Amount.Text(10))
	blindingStr := fmt.Sprintf("Blinding: %s", commitment.Blinding.Text(10))
	ownerPubKey := fmt.Sprintf("OwnerPubKey: %s", formatPoint(commitment.OwnerPubKey))
	viewPubKey := fmt.Sprintf("ViewPubKey: %s", formatPoint(commitment.ViewPubKey))
	auditPubKey := fmt.Sprintf("AuditPubKey: %s", formatPoint(commitment.AuditPubKey))
	freezeFlag := fmt.Sprintf("FreezeFlag: %s", commitment.FreezeFlag.Text(10))
	return fmt.Sprintf("Commitment(%s,%s,%s,%s,%s,%s,%s,%s)",
		assetStr,
		amountStr,
		blindingStr,
		ownerPubKey,
		viewPubKey,
		auditPubKey,
		freezeFlag)
}

func (commitment *Commitment) Compute() fr.Element {
	spentHasher := poseidon2.NewMerkleDamgardHasher()

	spentSecKeyBytes := commitment.SpentSecKey.Bytes()
	spentHasher.Write(spentSecKeyBytes[:])

	spentAddress := spentHasher.Sum(nil)

	hasher := poseidon2.NewMerkleDamgardHasher()

	assetBytes := commitment.Asset.Bytes()
	amountBytes := commitment.Amount.Bytes()
	ownerPubKeyXBytes := commitment.OwnerPubKey.X.Bytes()
	ownerPubKeyYBytes := commitment.OwnerPubKey.Y.Bytes()
	viewPubKeyXBytes := commitment.ViewPubKey.X.Bytes()
	viewPubKeyYBytes := commitment.ViewPubKey.Y.Bytes()
	auditPubKeyXBytes := commitment.AuditPubKey.X.Bytes()
	auditPubKeyYBytes := commitment.AuditPubKey.Y.Bytes()
	freezeFlagBytes := commitment.FreezeFlag.Bytes()
	blindingBytes := commitment.Blinding.Bytes()

	hasher.Write(assetBytes[:])
	hasher.Write(amountBytes[:])
	hasher.Write(ownerPubKeyXBytes[:])
	hasher.Write(ownerPubKeyYBytes[:])
	hasher.Write(spentAddress)
	hasher.Write(viewPubKeyXBytes[:])
	hasher.Write(viewPubKeyYBytes[:])
	hasher.Write(auditPubKeyXBytes[:])
	hasher.Write(auditPubKeyYBytes[:])
	hasher.Write(freezeFlagBytes[:])

	resBytes := hasher.Sum(blindingBytes[:])

	res := fr.Element{}
	res.Unmarshal(resBytes)

	return res
}

func GenerateCommitment(seed int64) (*Commitment, *fr.Element) {
	rnd := rand.New(rand.NewSource(seed))

	max := new(big.Int).Lsh(big.NewInt(1), 254)

	ownerSecKey := new(big.Int).Rand(rnd, max)
	ownerPubKey := utils.BuildPublicKey(*ownerSecKey)

	viewSecKey := new(big.Int).Rand(rnd, max)
	viewPubKey := utils.BuildPublicKey(*viewSecKey)

	auditSecKey := new(big.Int).Rand(rnd, max)
	auditPubKey := utils.BuildPublicKey(*auditSecKey)

	amount := rnd.Uint64()
	asset := rnd.Uint64()
	blinding := rnd.Uint64()

	spentSecKeyBigInt := new(big.Int).Rand(rnd, max)
	spentSecKey := fr.Element{}
	spentSecKey.SetBigInt(spentSecKeyBigInt)

	commitment := &Commitment{
		Asset:       fr.NewElement(asset),
		Amount:      fr.NewElement(amount),
		OwnerPubKey: ownerPubKey,
		SpentSecKey: spentSecKey,
		ViewPubKey:  viewPubKey,
		AuditPubKey: auditPubKey,
		FreezeFlag:  fr.NewElement(0),
		Blinding:    fr.NewElement(blinding),
	}

	return commitment, &spentSecKey
}
