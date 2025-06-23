package circuits

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon2"
	"github.com/consensys/gnark/frontend"
)

type NullifierGadget struct {
	CommitmentGadget
	PrivateKey frontend.Variable `gnark:"privateKey"`
}

func (gadget *NullifierGadget) Compute(api frontend.API) (frontend.Variable, error) {
	hasher, err := NewPoseidonHasher(api)
	if err != nil {
		return nil, fmt.Errorf("failed to create poseidon hasher: %w", err)
	}

	hasher.Write(gadget.Asset)
	hasher.Write(gadget.Amount)
	hasher.Write(gadget.Blinding)
	hasher.Write(gadget.PrivateKey)

	nullifier := hasher.Sum()

	return nullifier, nil
}

type Nullifier struct {
	Commitment
	PrivateKey fr.Element
}

func (nullifier *Nullifier) ToGadget() *NullifierGadget {
	return &NullifierGadget{
		CommitmentGadget: *nullifier.Commitment.ToGadget(),
		PrivateKey:       nullifier.PrivateKey,
	}
}

func (nullifier *Nullifier) Compute() fr.Element {
	hasher := poseidon2.NewMerkleDamgardHasher()

	asset_bytes := nullifier.Asset.Bytes()
	amount_bytes := nullifier.Amount.Bytes()
	blinding_bytes := nullifier.Blinding.Bytes()
	secret_key_bytes := nullifier.PrivateKey.Bytes()

	hasher.Write(asset_bytes[:])
	hasher.Write(amount_bytes[:])
	hasher.Write(blinding_bytes[:])

	res_bytes := hasher.Sum(secret_key_bytes[:])

	res := fr.Element{}
	res.Unmarshal(res_bytes)

	return res
}

func (nullifier *Nullifier) ToCommitment() *Commitment {
	return &Commitment{
		Asset:    nullifier.Asset,
		Amount:   nullifier.Amount,
		Blinding: nullifier.Blinding,
	}
}
