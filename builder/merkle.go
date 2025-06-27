package builder

import "github.com/consensys/gnark-crypto/ecc/bn254/fr"

type MerkleTree struct {
	tree map[int]fr.Element
}

func (mt *MerkleTree) Build(elems []fr.Element) {
	mt.tree = make(map[int]fr.Element)

	for i := 0; i < len(elems); i++ {
		mt.tree[i] = elems[i]
	}
}
