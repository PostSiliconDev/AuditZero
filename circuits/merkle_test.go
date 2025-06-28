package circuits_test

import (
	"fmt"
	"hide-pay/builder"
	"hide-pay/circuits"
	"hide-pay/utils"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon2"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type MerkleProofGadgetCircuit struct {
	circuits.MerkleProofGadget
	Root frontend.Variable `gnark:"root"`
}

func (circuit *MerkleProofGadgetCircuit) Define(api frontend.API) error {
	hasher, err := utils.NewPoseidonHasher(api)
	if err != nil {
		return fmt.Errorf("failed to create poseidon hasher: %w", err)
	}

	root := circuit.VerifyProof(api, hasher)

	api.AssertIsEqual(root, circuit.Root)

	return nil
}

func TestMerkleProofGadget(t *testing.T) {
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

	depth := 10

	mt := builder.NewMerkleTree(depth, hasher)
	mt.Build(elems)

	proof := mt.GetProof(5)
	proof.Verify()

	root := mt.GetRoot()

	witness := MerkleProofGadgetCircuit{
		MerkleProofGadget: *proof.ToGadget(),
		Root:              root,
	}

	circuit := MerkleProofGadgetCircuit{
		MerkleProofGadget: circuits.NewMerkleProofGadget(depth),
	}

	assert := test.NewAssert(t)

	assert.ProverSucceeded(&circuit, &witness, test.WithCurves(ecc.BN254))
}
