package circuits

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon2"
	"github.com/consensys/gnark/frontend"
)

type CommitmentCircuit struct {
	Asset      frontend.Variable `gnark:"asset"`
	Amount     frontend.Variable `gnark:"amount"`
	Blinding   frontend.Variable `gnark:"blinding"`
	Commitment frontend.Variable `gnark:"commitment,public"`
}

func NewCommitmentCircuit() *CommitmentCircuit {
	return &CommitmentCircuit{}
}

func (circuit *CommitmentCircuit) Define(api frontend.API) error {
	hasher, err := NewPoseidonHasher(api)
	if err != nil {
		return fmt.Errorf("failed to create poseidon hasher: %w", err)
	}

	hasher.Write(circuit.Asset)
	hasher.Write(circuit.Amount)
	hasher.Write(circuit.Blinding)

	commitment := hasher.Sum()
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

	fmt.Println("asset_bytes", asset_bytes)
	fmt.Println("amount_bytes", amount_bytes)
	fmt.Println("blinding_bytes", blinding_bytes)

	hasher.Write(asset_bytes[:])
	hasher.Write(amount_bytes[:])

	res_bytes := hasher.Sum(blinding_bytes[:])

	res := fr.Element{}
	res.Unmarshal(res_bytes)

	return res
}

func (commitment *Commitment) ToCircuit() *CommitmentCircuit {
	commitment_hash := commitment.Compute()

	return &CommitmentCircuit{
		Asset:      commitment.Asset,
		Amount:     commitment.Amount,
		Blinding:   commitment.Blinding,
		Commitment: commitment_hash,
	}
}
