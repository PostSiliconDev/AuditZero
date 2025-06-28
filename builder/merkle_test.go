package builder_test

import (
	"fmt"
	"hide-pay/builder"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon2"
	"github.com/stretchr/testify/assert"
)

func TestMerkleTreeBuild(t *testing.T) {
	elems := []fr.Element{
		fr.NewElement(1),
		fr.NewElement(2),
		fr.NewElement(3),
		fr.NewElement(4),
		fr.NewElement(5),
		fr.NewElement(6),
		fr.NewElement(7),
	}

	hasher := poseidon2.NewMerkleDamgardHasher()

	mt := builder.NewMerkleTree(34, hasher)

	mt.Build(elems)
	// mt.PrintTree()

	proof := mt.GetProof(5)
	// proof.PrintProof()

	fmt.Println("proof root")
	proofRoot := proof.Verify()
	// fmt.Println(proofRoot.Text(10))

	merkleRoot := mt.GetRoot()
	// fmt.Println(merkleRoot.Text(10))
	assert.Equal(t, proofRoot, merkleRoot)
}
