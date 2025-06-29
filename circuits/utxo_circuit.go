package circuits

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
)

type UTXOCircuit struct {
	UTXOGadget
	UTXOResultGadget
}

func NewUTXOCircuit(allAssetSize int, depth int, nullifierSize int, commitmentSize int) *UTXOCircuit {
	return &UTXOCircuit{
		UTXOGadget:       *NewUTXOGadget(allAssetSize, depth, nullifierSize, commitmentSize),
		UTXOResultGadget: *NewUTXOResultGadget(nullifierSize, commitmentSize),
	}
}

func (circuit *UTXOCircuit) Define(api frontend.API) error {
	utxoResult, err := circuit.UTXOGadget.BuildAndCheck(api)
	if err != nil {
		return fmt.Errorf("failed to build and check UTXO: %w", err)
	}

	for i := range circuit.UTXOResultGadget.Nullifiers {
		api.AssertIsEqual(circuit.UTXOResultGadget.Nullifiers[i], utxoResult.Nullifiers[i])
	}

	for i := range circuit.UTXOResultGadget.Commitments {
		api.AssertIsEqual(circuit.UTXOResultGadget.Commitments[i], utxoResult.Commitments[i])
	}

	for i := range circuit.UTXOResultGadget.OwnerMemoHashes {
		api.AssertIsEqual(circuit.UTXOResultGadget.OwnerMemoHashes[i], utxoResult.OwnerMemoHashes[i])
	}

	for i := range circuit.UTXOResultGadget.AuditMemoHashes {
		api.AssertIsEqual(circuit.UTXOResultGadget.AuditMemoHashes[i], utxoResult.AuditMemoHashes[i])
	}

	// api.AssertIsEqual(circuit.UTXOResultGadget.Root, utxoResult.Root)

	return nil
}
