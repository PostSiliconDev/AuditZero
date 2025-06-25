package circuits

import "github.com/consensys/gnark-crypto/ecc/bn254/fr"

type MerkleGadget struct{}

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
