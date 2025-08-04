package circuits

import (
	"fmt"
	"hide-pay/utils"

	"github.com/consensys/gnark/frontend"
)

type NullifierGadget struct {
	CommitmentGadget
	PrivateKey frontend.Variable `gnark:"privateKey"`
}

func (gadget *NullifierGadget) Compute(api frontend.API) (frontend.Variable, error) {
	hasher, err := utils.NewPoseidonHasher(api)
	if err != nil {
		return nil, fmt.Errorf("failed to create poseidon hasher: %w", err)
	}

	commitment, err := gadget.CommitmentGadget.Compute(api)
	if err != nil {
		return nil, fmt.Errorf("failed to compute commitment: %w", err)
	}

	hasher.Write(commitment)
	hasher.Write(gadget.PrivateKey)

	nullifier := hasher.Sum()

	return nullifier, nil
}
