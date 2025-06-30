package builder

import (
	"fmt"
	"hide-pay/circuits"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon2"
)

type Commitment struct {
	Asset    fr.Element
	Amount   fr.Element
	Blinding fr.Element
}

func (commitment *Commitment) ToGadget() *circuits.CommitmentGadget {
	return &circuits.CommitmentGadget{
		Asset:    commitment.Asset,
		Amount:   commitment.Amount,
		Blinding: commitment.Blinding,
	}
}

func (commitment *Commitment) String() string {
	return fmt.Sprintf("Commitment(Asset: %s, Amount: %s, Blinding: %s)", commitment.Asset.Text(10), commitment.Amount.Text(10), commitment.Blinding.Text(10))
}

func (commitment *Commitment) Compute() fr.Element {
	hasher := poseidon2.NewMerkleDamgardHasher()

	asset_bytes := commitment.Asset.Bytes()
	amount_bytes := commitment.Amount.Bytes()
	blinding_bytes := commitment.Blinding.Bytes()

	hasher.Write(asset_bytes[:])
	hasher.Write(amount_bytes[:])

	res_bytes := hasher.Sum(blinding_bytes[:])

	res := fr.Element{}
	res.Unmarshal(res_bytes)

	return res
}
