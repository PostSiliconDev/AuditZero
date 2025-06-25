package circuits

import (
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/frontend"
)

type MerkleGadget struct {
	Path      []frontend.Variable `gnark:"path"`
	Direction []frontend.Variable `gnark:"direction"`
}

type MerkleProofNode struct {
	Left      fr.Element
	Middle    fr.Element
	Right     fr.Element
	Direction int
}

type MerkleProof struct {
	Root fr.Element
	Path []MerkleProofNode
}

func (proof *MerkleProof) Verify() error {
	return nil
}
