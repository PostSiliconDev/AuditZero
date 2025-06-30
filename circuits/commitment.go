package circuits

import (
	"fmt"
	"hide-pay/utils"

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
