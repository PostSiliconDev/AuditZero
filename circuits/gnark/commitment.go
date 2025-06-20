package circuits

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon2"
	"github.com/consensys/gnark/frontend"
)

type CommitmentGadget struct {
	api frontend.API
}

func NewCommitmentGadget(api frontend.API) *CommitmentGadget {
	return &CommitmentGadget{
		api: api,
	}
}

func (gadget *CommitmentGadget) Compute(output *OutputGadget) (frontend.Variable, error) {
	hasher, err := NewPoseidonHasher(gadget.api)
	if err != nil {
		return nil, fmt.Errorf("failed to create poseidon hasher: %w", err)
	}

	hasher.Write(output.Asset)
	hasher.Write(output.Amount)
	hasher.Write(output.Blinding)

	commitment := hasher.Sum()

	return commitment, nil
}

type CommitmentCircuit struct {
	Output     OutputGadget
	Commitment frontend.Variable `gnark:"commitment,public"`
}

func NewCommitmentCircuit() *CommitmentCircuit {
	return &CommitmentCircuit{}
}

func (circuit *CommitmentCircuit) Define(api frontend.API) error {
	gadget := NewCommitmentGadget(api)

	commitment, err := gadget.Compute(&circuit.Output)
	if err != nil {
		return fmt.Errorf("failed to compute commitment: %w", err)
	}
	api.AssertIsEqual(circuit.Commitment, commitment)

	return nil
}

type Commitment struct {
	Asset    fr.Element
	Amount   fr.Element
	Blinding fr.Element
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

func (commitment *Commitment) ToWitness() *CommitmentCircuit {
	commitment_hash := commitment.Compute()

	return &CommitmentCircuit{
		Output: OutputGadget{
			Asset:    commitment.Asset,
			Amount:   commitment.Amount,
			Blinding: commitment.Blinding,
		},
		Commitment: commitment_hash,
	}
}
