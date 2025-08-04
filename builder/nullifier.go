package builder

import (
	"fmt"
	"hide-pay/circuits"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon2"
)

type Nullifier struct {
	Commitment
	SpentPrivateKey fr.Element
}

func (nullifier *Nullifier) ToString() string {
	return fmt.Sprintf("Commitment: %s,PrivateKey: %s", nullifier.Commitment.String(), nullifier.SpentPrivateKey.Text(10))
}

func (nullifier *Nullifier) ToGadget() *circuits.NullifierGadget {
	return &circuits.NullifierGadget{
		CommitmentGadget: *nullifier.Commitment.ToGadget(),
		PrivateKey:       nullifier.SpentPrivateKey,
	}
}

func (nullifier *Nullifier) Compute() fr.Element {
	hasher := poseidon2.NewMerkleDamgardHasher()

	commitment := nullifier.Commitment.Compute()

	commitmentBytes := commitment.Bytes()
	spentPrivateKeyBytes := nullifier.SpentPrivateKey.Bytes()

	hasher.Write(commitmentBytes[:])

	res_bytes := hasher.Sum(spentPrivateKeyBytes[:])

	res := fr.Element{}
	res.Unmarshal(res_bytes)

	return res
}
