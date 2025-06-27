package circuits_test

import (
	circuits "hide-pay/circuits/gnark"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"github.com/stretchr/testify/assert"
)

func buildPureLeftMerkleProof() (*circuits.MerkleProof, fr.Element, error) {
	proof := circuits.MerkleProof{
		Path: [circuits.MAX_MERKLE_DEPTH]circuits.MerkleProofNode{},
	}

	current := fr.NewElement(100)

	for i := 0; i < circuits.MAX_MERKLE_DEPTH; i++ {
		proof.Path[i].Left = current
		proof.Path[i].Middle = fr.NewElement(0)
		proof.Path[i].Right = fr.NewElement(0)
		proof.Path[i].Direction = 0

		current = circuits.HashMerkleNode(proof.Path[i].Left, proof.Path[i].Middle, proof.Path[i].Right)
	}

	return &proof, current, nil
}

func TestMerkleProof(t *testing.T) {
	proof, rootBuild, err := buildPureLeftMerkleProof()
	assert.NoError(t, err)

	root, err := proof.Verify()
	assert.NoError(t, err)
	assert.Equal(t, root, rootBuild)
}

type MerkleCircuit struct {
	circuits.MerkleGadget
	Root frontend.Variable `gnark:"root,public"`
}

func (c *MerkleCircuit) Define(api frontend.API) error {
	root, err := c.MerkleGadget.Verify(api)
	if err != nil {
		return err
	}

	api.AssertIsEqual(root, c.Root)
	return nil
}

func TestMerkleCircuit(t *testing.T) {
	proof, root, err := buildPureLeftMerkleProof()
	assert.NoError(t, err)

	circuit := MerkleCircuit{
		MerkleGadget: *circuits.NewMerkleGadget(),
	}

	gadget, err := proof.ToGadget()
	assert.NoError(t, err)

	witness := MerkleCircuit{
		MerkleGadget: *gadget,
		Root:         root,
	}

	assert := test.NewAssert(t)
	options := test.WithCurves(ecc.BN254)

	assert.ProverSucceeded(&circuit, &witness, options)
}

func TestMerkleTree(t *testing.T) {
	commitments := []fr.Element{
		fr.NewElement(0),
		fr.NewElement(1),
		fr.NewElement(2),
		fr.NewElement(3),
		fr.NewElement(4),
		fr.NewElement(5),
		fr.NewElement(6),
		fr.NewElement(7),
		fr.NewElement(8),
		fr.NewElement(9),
		fr.NewElement(10),
		fr.NewElement(11),
		fr.NewElement(12),
		fr.NewElement(13),
	}

	tree, err := circuits.BuildMerkleTree(commitments)
	assert.NoError(t, err)

	treeRoot := tree.GetRoot()

	proof, err := tree.GetProof(5)
	assert.NoError(t, err)

	// for i, v := range proof.Path {
	// 	fmt.Println("index:", i, "direction:", v.Direction, ",value:", v.Left.Text(10), v.Middle.Text(10), v.Right.Text(10))
	// }

	root, err := proof.Verify()
	assert.NoError(t, err)

	assert.Equal(t, root, treeRoot)
}
