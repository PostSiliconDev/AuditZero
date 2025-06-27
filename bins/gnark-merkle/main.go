package main

import (
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash"
)

// MerkleProof stores the path, the root hash and an helper for the Merkle proof.
type MerkleProof struct {

	// RootHash root of the Merkle tree
	RootHash frontend.Variable

	// Path path of the Merkle proof
	Path []frontend.Variable
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
func (mp *MerkleProof) VerifyProof(api frontend.API, h hash.FieldHasher, leaf frontend.Variable) {

	depth := len(mp.Path) - 1
	sum := mp.Path[0]

	// The binary decomposition is the bitwise negation of the order of hashes ->
	// If the path in the plain go code is 					0 1 1 0 1 0
	// The binary decomposition of the leaf index will be 	1 0 0 1 0 1 (little endian)
	binLeaf := api.ToBinary(leaf, depth)

	for i := 1; i < len(mp.Path); i++ { // the size of the loop is fixed -> one circuit per size
		d1 := api.Select(binLeaf[i-1], mp.Path[i], sum)
		d2 := api.Select(binLeaf[i-1], sum, mp.Path[i])
		sum = nodeSum(h, d1, d2)
	}

	// Compare our calculated Merkle root to the desired Merkle root.
	api.AssertIsEqual(sum, mp.RootHash)
}

type MerkleTree struct {
	tree map[int]fr.Element
}

func (mt *MerkleTree) Build(elems []fr.Element) {
	mt.tree = make(map[int]fr.Element)

	for i := 0; i < len(elems); i++ {
		mt.tree[i] = elems[i]
	}
}

func main() {

	// witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	// if err != nil {
	// 	panic(fmt.Sprintf("failed to create witness: %v", err))
	// }

	// publicWitness, err := witness.Public()
	// if err != nil {
	// 	panic(fmt.Sprintf("failed to create public witness: %v", err))
	// }

	// cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	// if err != nil {
	// 	panic(fmt.Sprintf("failed to compile circuit: %v", err))
	// }

	// pk, vk, err := groth16.Setup(cs)
	// if err != nil {
	// 	panic(fmt.Sprintf("failed to setup circuit: %v", err))
	// }

	// proof, err := groth16.Prove(cs, pk, witness)
	// if err != nil {
	// 	panic(fmt.Sprintf("failed to prove circuit: %v", err))
	// }

	// err = groth16.Verify(proof, vk, publicWitness)
	// if err != nil {
	// 	panic(fmt.Sprintf("failed to verify circuit: %v", err))
	// } else {
	// 	fmt.Println("Proof verified")
	// }
}
