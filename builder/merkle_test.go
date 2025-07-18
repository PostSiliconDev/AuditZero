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
	}

	hasher := poseidon2.NewMerkleDamgardHasher()

	mt := builder.NewMerkleTree(34, hasher)

	for _, elem := range elems {
		mt.AppendSingle(elem)
	}

	mt.PrintTree()

	proof := mt.GetProof(2)
	proof.PrintProof()

	fmt.Println("proof root")
	proofRoot := proof.Verify()
	fmt.Println(proofRoot.Text(10))

	merkleRoot := mt.GetRoot()
	fmt.Println(merkleRoot.Text(10))
	assert.Equal(t, proofRoot, merkleRoot)
}
