package circuits

import (
	"fmt"
	"math"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	poseidonbn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon2"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash"
	"github.com/consensys/gnark/std/permutation/poseidon2"
)

const (
	MAX_MERKLE_DEPTH = 24
	MERKLE_ROOT_POS  = 423644304720
)

type MerkleGadget struct {
	Path      [MAX_MERKLE_DEPTH * 3]frontend.Variable `gnark:"path"`
	Direction [MAX_MERKLE_DEPTH * 3]frontend.Variable `gnark:"direction"`
}

func NewMerkleGadget() *MerkleGadget {
	return &MerkleGadget{}
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
	Path [MAX_MERKLE_DEPTH]MerkleProofNode
}

func (proof *MerkleProof) Verify() (fr.Element, error) {
	if len(proof.Path) != MAX_MERKLE_DEPTH {
		return fr.NewElement(0), fmt.Errorf("invalid proof length")
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

	return hashElement, nil
}

func (proof *MerkleProof) ToGadget() (*MerkleGadget, error) {
	path := [MAX_MERKLE_DEPTH * 3]frontend.Variable{}
	direction := [MAX_MERKLE_DEPTH * 3]frontend.Variable{}

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

func HashMerkleNode(left, middle, right fr.Element) fr.Element {
	leftBytes := left.Bytes()
	middleBytes := middle.Bytes()
	rightBytes := right.Bytes()

	hasher := poseidonbn254.NewMerkleDamgardHasher()
	hasher.Write(leftBytes[:])
	hasher.Write(middleBytes[:])
	hasher.Write(rightBytes[:])

	hash := hasher.Sum(nil)
	hashElement := fr.NewElement(0)
	hashElement.SetBytes(hash)

	return hashElement
}

type MerkleTree struct {
	Tree map[int]fr.Element
}

func BuildMerkleTree(commitments []fr.Element) (*MerkleTree, error) {
	treeDepth := MAX_MERKLE_DEPTH

	tree := &MerkleTree{
		Tree: make(map[int]fr.Element),
	}

	for i := range commitments {
		tree.Tree[i] = commitments[i]
	}

	index := 0
	numNodeThisLevel := len(commitments)/3 + 1

	for i := 0; i < treeDepth; i++ {
		nextLevelIndex := index + int(math.Pow(float64(3), float64(treeDepth-i)))
		index_step := treeDepth - i

		for j := 0; j < numNodeThisLevel; j++ {
			left := tree.Tree[index+j*3]
			middle := tree.Tree[index+j*3+1]
			right := tree.Tree[index+j*3+2]
			tree.Tree[nextLevelIndex+j] = HashMerkleNode(left, middle, right)
		}

		numNodeThisLevel = numNodeThisLevel/3 + 1
		index += int(math.Pow(float64(3), float64(index_step)))
	}

	return tree, nil
}

func (tree *MerkleTree) GetRoot() fr.Element {
	return tree.Tree[MERKLE_ROOT_POS]
}

func (tree *MerkleTree) GetProof(nodeIndex int) (*MerkleProof, error) {
	treeDepth := MAX_MERKLE_DEPTH

	proof := &MerkleProof{}

	numNodeThisLevel := nodeIndex

	index := 0
	for i := 0; i < MAX_MERKLE_DEPTH; i++ {
		index_step := treeDepth - i

		beginOffestThisLevel := (numNodeThisLevel / 3) * 3

		proof.Path[i].Left = tree.Tree[index+beginOffestThisLevel]
		proof.Path[i].Middle = tree.Tree[index+beginOffestThisLevel+1]
		proof.Path[i].Right = tree.Tree[index+beginOffestThisLevel+2]

		splited9ram := numNodeThisLevel % 9
		if splited9ram == 0 || splited9ram == 1 || splited9ram == 2 {
			proof.Path[i].Direction = 0
		} else if splited9ram == 3 || splited9ram == 4 || splited9ram == 5 {
			proof.Path[i].Direction = 1
		} else if splited9ram == 6 || splited9ram == 7 || splited9ram == 8 {
			proof.Path[i].Direction = 2
		}

		// fmt.Println("--------------------------------")
		// fmt.Println("numNodeThisLevel", numNodeThisLevel)
		// fmt.Println("beginOffestThisLevel", beginOffestThisLevel)
		// fmt.Println("index", index)
		// fmt.Println("i", i)

		numNodeThisLevel = numNodeThisLevel/3 + 1
		index += int(math.Pow(float64(3), float64(index_step)))
	}

	return proof, nil
}
