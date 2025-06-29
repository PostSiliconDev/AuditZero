package circuits

import (
	"fmt"
	"hide-pay/utils"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon2"
	"github.com/consensys/gnark/frontend"
)

type CommitmentGadget struct {
	Asset    frontend.Variable `gnark:"asset"`
	Amount   frontend.Variable `gnark:"amount"`
	Blinding frontend.Variable `gnark:"blinding"`
}

func (gadget *CommitmentGadget) Compute(api frontend.API) (frontend.Variable, error) {
	hasher, err := utils.NewPoseidonHasher(api)
	if err != nil {
		return nil, fmt.Errorf("failed to create poseidon hasher: %w", err)
	}

	hasher.Write(gadget.Asset)
	hasher.Write(gadget.Amount)
	hasher.Write(gadget.Blinding)

	commitment := hasher.Sum()

	return commitment, nil
}

type Commitment struct {
	Asset    fr.Element
	Amount   fr.Element
	Blinding fr.Element
}

func (commitment *Commitment) ToGadget() *CommitmentGadget {
	return &CommitmentGadget{
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
