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

type NullifierCircuit struct {
	NullifierGadget
	Nullifier frontend.Variable `gnark:"nullifier,public"`
}

func NewNullifierCircuit() *NullifierCircuit {
	return &NullifierCircuit{}
}

func (circuit *NullifierCircuit) Define(api frontend.API) error {
	gadget := NullifierGadget{
		CommitmentGadget: CommitmentGadget{
			Asset:    circuit.Asset,
			Amount:   circuit.Amount,
			Blinding: circuit.Blinding,
		},
		PrivateKey: circuit.PrivateKey,
	}
	nullifier, err := gadget.Compute(api)
	if err != nil {
		return fmt.Errorf("failed to compute nullifier: %w", err)
	}
	api.AssertIsEqual(circuit.Nullifier, nullifier)

	return nil
}

type Nullifier struct {
	Asset      fr.Element
	Amount     fr.Element
	Blinding   fr.Element
	PrivateKey fr.Element
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

func (nullifier *Nullifier) ToWitness() *NullifierCircuit {
	nullifier_hash := nullifier.Compute()

	return &NullifierCircuit{
		NullifierGadget: NullifierGadget{
			CommitmentGadget: CommitmentGadget{
				Asset:    nullifier.Asset,
				Amount:   nullifier.Amount,
				Blinding: nullifier.Blinding,
			},
			PrivateKey: nullifier.PrivateKey,
		},
		Nullifier: nullifier_hash,
	}
}

func (nullifier *Nullifier) ToCommitment() *Commitment {
	return &Commitment{
		Asset:    nullifier.Asset,
		Amount:   nullifier.Amount,
		Blinding: nullifier.Blinding,
	}
}
