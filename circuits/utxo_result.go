package circuits

// type UTXOResultGadget struct {
// 	Nullifiers      []frontend.Variable `gnark:"nullifiers,public"`
// 	Commitments     []frontend.Variable `gnark:"commitments,public"`
// 	OwnerMemoHashes []frontend.Variable `gnark:"ownerMemoHashes,public"`
// 	AuditMemoHashes []frontend.Variable `gnark:"auditMemoHashes,public"`
// 	MerkleRoot      frontend.Variable   `gnark:"merkleRoot,public"`
// }

// func NewUTXOResultGadget(nullifierSize int, commitmentSize int) *UTXOResultGadget {
// 	return &UTXOResultGadget{
// 		Nullifiers:      make([]frontend.Variable, nullifierSize),
// 		Commitments:     make([]frontend.Variable, commitmentSize),
// 		OwnerMemoHashes: make([]frontend.Variable, commitmentSize),
// 		AuditMemoHashes: make([]frontend.Variable, commitmentSize),
// 	}
// }
