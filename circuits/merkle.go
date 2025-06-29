package circuits

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash"
)

// MerkleProof stores the path, the root hash and an helper for the Merkle proof.
type MerkleProofGadget struct {
	// Path path of the Merkle proof
	Path []frontend.Variable `gnark:"path"`

	Leaf frontend.Variable `gnark:"leaf"`
}

func NewMerkleProofGadget(pathSize int) MerkleProofGadget {
	return MerkleProofGadget{
		Path: make([]frontend.Variable, pathSize),
	}
}

// nodeSum returns the hash created from data inserted to form a leaf.
// Without domain separation.
func nodeSum(h hash.FieldHasher, a, b frontend.Variable) frontend.Variable {
	h.Reset()
	h.Write(a, b)
	res := h.Sum()

	return res
}

// VerifyProof takes a Merkle root, a proofSet, and a proofIndex and returns
// true if the first element of the proof set is a leaf of data in the Merkle
// root. False is returned if the proof set or Merkle root is nil, and if
// 'numLeaves' equals 0.
func (mp *MerkleProofGadget) VerifyProof(api frontend.API, h hash.FieldHasher) frontend.Variable {

	depth := len(mp.Path) - 1
	sum := mp.Path[0]

	// The binary decomposition is the bitwise negation of the order of hashes ->
	// If the path in the plain go code is 					0 1 1 0 1 0
	// The binary decomposition of the leaf index will be 	1 0 0 1 0 1 (little endian)
	binLeaf := api.ToBinary(mp.Leaf, depth)

	for i := 1; i < len(mp.Path); i++ { // the size of the loop is fixed -> one circuit per size
		d1 := api.Select(binLeaf[i-1], mp.Path[i], sum)
		d2 := api.Select(binLeaf[i-1], sum, mp.Path[i])
		sum = nodeSum(h, d1, d2)
	}

	return sum
}
