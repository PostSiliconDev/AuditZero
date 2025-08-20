package circuits

// type UTXOCircuit struct {
// 	UTXO   UTXOGadget
// 	Result UTXOResultGadget
// }

// func NewUTXOCircuit(allAssetSize int, depth int, nullifierSize int, commitmentSize int) *UTXOCircuit {
// 	return &UTXOCircuit{
// 		UTXO:   *NewUTXOGadget(allAssetSize, depth, nullifierSize, commitmentSize),
// 		Result: *NewUTXOResultGadget(nullifierSize, commitmentSize),
// 	}
// }

// func (circuit *UTXOCircuit) Define(api frontend.API) error {
// 	utxoResult, err := circuit.UTXO.BuildAndCheck(api)
// 	if err != nil {
// 		return fmt.Errorf("failed to build and check UTXO: %w", err)
// 	}

// 	for i := range circuit.Result.Nullifiers {
// 		api.AssertIsEqual(circuit.Result.Nullifiers[i], utxoResult.Nullifiers[i])
// 	}

// 	for i := range circuit.Result.Commitments {
// 		api.AssertIsEqual(circuit.Result.Commitments[i], utxoResult.Commitments[i])
// 	}

// 	for i := range circuit.Result.OwnerMemoHashes {
// 		api.AssertIsEqual(circuit.Result.OwnerMemoHashes[i], utxoResult.OwnerMemoHashes[i])
// 	}

// 	for i := range circuit.Result.AuditMemoHashes {
// 		api.AssertIsEqual(circuit.Result.AuditMemoHashes[i], utxoResult.AuditMemoHashes[i])
// 	}

// 	api.AssertIsEqual(circuit.Result.MerkleRoot, utxoResult.MerkleRoot)

// 	return nil
// }
