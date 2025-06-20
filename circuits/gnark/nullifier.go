package circuits

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon2"
	"github.com/consensys/gnark/frontend"
)

type NullifierGadget struct {
	api frontend.API
}

func NewNullifierGadget(api frontend.API) *NullifierGadget {
	return &NullifierGadget{
		api: api,
	}
}

func (gadget *NullifierGadget) Compute(output *OutputGadget, privateKey frontend.Variable) (frontend.Variable, error) {
	hasher, err := NewPoseidonHasher(gadget.api)
	if err != nil {
		return nil, fmt.Errorf("failed to create poseidon hasher: %w", err)
	}

	hasher.Write(output.Asset)
	hasher.Write(output.Amount)
	hasher.Write(output.Blinding)
	hasher.Write(privateKey)

	nullifier := hasher.Sum()

	return nullifier, nil
}

type NullifierCircuit struct {
	Output     OutputGadget
	PrivateKey frontend.Variable `gnark:"privateKey"`
	Nullifier  frontend.Variable `gnark:"nullifier,public"`
}

func NewNullifierCircuit() *NullifierCircuit {
	return &NullifierCircuit{}
}

func (circuit *NullifierCircuit) Define(api frontend.API) error {
	gadget := NewNullifierGadget(api)
	nullifier, err := gadget.Compute(&circuit.Output, circuit.PrivateKey)
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
		Output: OutputGadget{
			Asset:    nullifier.Asset,
			Amount:   nullifier.Amount,
			Blinding: nullifier.Blinding,
		},
		PrivateKey: nullifier.PrivateKey,
		Nullifier:  nullifier_hash,
	}
}

func (nullifier *Nullifier) ToCommitment() *Commitment {
	return &Commitment{
		Asset:    nullifier.Asset,
		Amount:   nullifier.Amount,
		Blinding: nullifier.Blinding,
	}
}
