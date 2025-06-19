package circuits

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon2"
	"github.com/consensys/gnark/frontend"
)

type NullifierCircuit struct {
	Asset      frontend.Variable `gnark:"asset"`
	Amount     frontend.Variable `gnark:"amount"`
	Blinding   frontend.Variable `gnark:"blinding"`
	PrivateKey frontend.Variable `gnark:"privateKey"`
	Nullifier  frontend.Variable `gnark:"nullifier,public"`
}

func (circuit *NullifierCircuit) Define(api frontend.API) error {
	hasher, err := NewPoseidonHasher(api)
	if err != nil {
		return fmt.Errorf("failed to create poseidon hasher: %w", err)
	}

	hasher.Write(circuit.Asset)
	hasher.Write(circuit.Amount)
	hasher.Write(circuit.Blinding)
	hasher.Write(circuit.PrivateKey)

	nullifier := hasher.Sum()
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

func (nullifier *Nullifier) ToCircuit() *NullifierCircuit {
	nullifier_hash := nullifier.Compute()

	return &NullifierCircuit{
		Asset:      nullifier.Asset,
		Amount:     nullifier.Amount,
		Blinding:   nullifier.Blinding,
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
