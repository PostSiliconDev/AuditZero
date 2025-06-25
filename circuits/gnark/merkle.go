package circuits

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	poseidonbn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon2"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash"
	"github.com/consensys/gnark/std/permutation/poseidon2"
)

const (
	MAX_MERKLE_DEPTH = 24
)

type MerkleGadget struct {
	Path      []frontend.Variable `gnark:"path"`
	Direction []frontend.Variable `gnark:"direction"`
}

func NewMerkleGadget() *MerkleGadget {
	return &MerkleGadget{
		Path:      make([]frontend.Variable, MAX_MERKLE_DEPTH*3),
		Direction: make([]frontend.Variable, MAX_MERKLE_DEPTH*3),
	}
}

func (gadget *MerkleGadget) Verify(api frontend.API) (frontend.Variable, error) {
	if len(gadget.Path) != MAX_MERKLE_DEPTH*3 || len(gadget.Direction) != MAX_MERKLE_DEPTH*3 {
		return 0, fmt.Errorf("invalid path or direction length")
	}

	params := poseidonbn254.GetDefaultParameters()
	for i := 0; i < MAX_MERKLE_DEPTH-1; i++ {
		perm, err := poseidon2.NewPoseidon2FromParameters(api, params.Width, params.NbFullRounds, params.NbPartialRounds)
		if err != nil {
			return 0, err
		}

		hasher := hash.NewMerkleDamgardHasher(api, perm, 0)
		if err != nil {
			return 0, err
		}

		hasher.Write(gadget.Path[i*3], gadget.Path[i*3+1], gadget.Path[i*3+2])
		hash := hasher.Sum()

		gadget.Path[i*3] = api.Mul(gadget.Path[i*3], hash)
		gadget.Path[i*3+1] = api.Mul(gadget.Path[i*3+1], hash)
		gadget.Path[i*3+2] = api.Mul(gadget.Path[i*3+2], hash)
	}
	perm, err := poseidon2.NewPoseidon2FromParameters(api, params.Width, params.NbFullRounds, params.NbPartialRounds)
	if err != nil {
		return 0, err
	}

	hasher := hash.NewMerkleDamgardHasher(api, perm, 0)
	if err != nil {
		return 0, err
	}

	hasher.Write(gadget.Path[MAX_MERKLE_DEPTH*3-3], gadget.Path[MAX_MERKLE_DEPTH*3-2], gadget.Path[MAX_MERKLE_DEPTH*3-1])
	hash := hasher.Sum()

	return hash, nil
}

type MerkleProofNode struct {
	Left      fr.Element
	Middle    fr.Element
	Right     fr.Element
	Direction int
}

type MerkleProof struct {
	Path []MerkleProofNode
}

func (proof *MerkleProof) Verify(root fr.Element) error {
	if len(proof.Path) != MAX_MERKLE_DEPTH {
		return fmt.Errorf("invalid proof length")
	}

	for i := 0; i < MAX_MERKLE_DEPTH-1; i++ {
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

		if proof.Path[i].Direction == 0 {
			proof.Path[i+1].Left = hashElement
		} else if proof.Path[i].Direction == 1 {
			proof.Path[i+1].Middle = hashElement
		} else if proof.Path[i].Direction == 2 {
			proof.Path[i+1].Right = hashElement
		}
	}

	hasher := poseidonbn254.NewMerkleDamgardHasher()
	leftBytes := proof.Path[MAX_MERKLE_DEPTH-1].Left.Bytes()
	middleBytes := proof.Path[MAX_MERKLE_DEPTH-1].Middle.Bytes()
	rightBytes := proof.Path[MAX_MERKLE_DEPTH-1].Right.Bytes()

	hasher.Write(leftBytes[:])
	hasher.Write(middleBytes[:])
	hasher.Write(rightBytes[:])

	hash := hasher.Sum(nil)
	hashElement := fr.NewElement(0)
	hashElement.SetBytes(hash)

	if hashElement != root {
		return fmt.Errorf("invalid root")
	}

	return nil
}

func (proof *MerkleProof) ToGadget() (*MerkleGadget, error) {
	path := make([]frontend.Variable, len(proof.Path)*3)
	direction := make([]frontend.Variable, len(proof.Path)*3)

	for i := range proof.Path {
		path[i*3] = proof.Path[i].Left
		path[i*3+1] = proof.Path[i].Middle
		path[i*3+2] = proof.Path[i].Right

		if proof.Path[i].Direction == 0 {
			direction[i*3] = 1
			direction[i*3+1] = 0
			direction[i*3+2] = 0
		} else if proof.Path[i].Direction == 1 {
			direction[i*3] = 0
			direction[i*3+1] = 1
			direction[i*3+2] = 0
		} else if proof.Path[i].Direction == 2 {
			direction[i*3] = 0
			direction[i*3+1] = 0
			direction[i*3+2] = 1
		} else {
			return nil, fmt.Errorf("invalid direction")
		}
	}

	return &MerkleGadget{Path: path, Direction: direction}, nil
}
