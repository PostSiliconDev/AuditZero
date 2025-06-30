package builder

import (
	"fmt"
	"hide-pay/circuits"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon2"
)

type Nullifier struct {
	circuits.Commitment
	PrivateKey fr.Element
}

func (nullifier *Nullifier) ToString() string {
	return fmt.Sprintf("%s%s%s%s", nullifier.Asset.Text(10), nullifier.Amount.Text(10), nullifier.Blinding.Text(10), nullifier.PrivateKey.Text(10))
}

func (nullifier *Nullifier) ToGadget() *circuits.NullifierGadget {
	return &circuits.NullifierGadget{
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

func (nullifier *Nullifier) ToCommitment() *circuits.Commitment {
	return &circuits.Commitment{
		Asset:    nullifier.Asset,
		Amount:   nullifier.Amount,
		Blinding: nullifier.Blinding,
	}
}
