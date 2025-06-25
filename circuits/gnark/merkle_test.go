package circuits_test

import (
	circuits "hide-pay/circuits/gnark"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	poseidonbn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon2"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"github.com/stretchr/testify/assert"
)

func buildPureLeftMerkleProof() (*circuits.MerkleProof, fr.Element, error) {
	proof := circuits.MerkleProof{
		Path: make([]circuits.MerkleProofNode, circuits.MAX_MERKLE_DEPTH),
	}

	current := fr.NewElement(100)

	for i := 0; i < circuits.MAX_MERKLE_DEPTH; i++ {
		proof.Path[i].Left = current
		proof.Path[i].Middle = fr.NewElement(0)
		proof.Path[i].Right = fr.NewElement(0)
		proof.Path[i].Direction = 0

		hasher := poseidonbn254.NewMerkleDamgardHasher()

		leftBytes := proof.Path[i].Left.Bytes()
		middleBytes := proof.Path[i].Middle.Bytes()
		rightBytes := proof.Path[i].Right.Bytes()

		hasher.Write(leftBytes[:])
		hasher.Write(middleBytes[:])
		hasher.Write(rightBytes[:])

		hash := hasher.Sum(nil)
		hashElement := fr.NewElement(0)
		hashElement.SetBytes(hash)

		current = hashElement
	}

	return &proof, current, nil
}

func TestMerkleProof(t *testing.T) {
	proof, root, err := buildPureLeftMerkleProof()
	assert.NoError(t, err)

	err = proof.Verify(root)
	assert.NoError(t, err)
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
