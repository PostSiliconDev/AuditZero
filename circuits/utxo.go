package circuits

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/rangecheck"
)

type UTXOGadget struct {
	AllAsset []frontend.Variable `gnark:"allAsset"`

	Nullifier []NullifierGadget `gnark:"nullifier"`

	Commitment []CommitmentGadget `gnark:"commitment"`

	EphemeralReceiverSecretKey []frontend.Variable  `gnark:"ephemeralReceiverSecretKey"`
	EphemeralAuditSecretKey    []frontend.Variable  `gnark:"ephemeralAuditSecretKey"`
	ReceiverPublicKey          [2]frontend.Variable `gnark:"receiverPublicKey"`
	AuditPublicKey             [2]frontend.Variable `gnark:"auditPublicKey"`
}

func NewUTXOGadget(allAssetSize int, nullifierSize int, commitmentSize int) *UTXOGadget {
	return &UTXOGadget{
		AllAsset: make([]frontend.Variable, allAssetSize),

		Nullifier:                  make([]NullifierGadget, nullifierSize),
		Commitment:                 make([]CommitmentGadget, commitmentSize),
		EphemeralReceiverSecretKey: make([]frontend.Variable, commitmentSize),
		EphemeralAuditSecretKey:    make([]frontend.Variable, commitmentSize),
	}
}

type UTXOResultGadget struct {
	Nullifiers      []frontend.Variable `gnark:"nullifiers,public"`
	Commitments     []frontend.Variable `gnark:"commitments,public"`
	OwnerMemoHashes []frontend.Variable `gnark:"ownerMemoHashes,public"`
	AuditMemoHashes []frontend.Variable `gnark:"auditMemoHashes,public"`
}

func NewUTXOResultGadget(nullifierSize int, commitmentSize int) *UTXOResultGadget {
	return &UTXOResultGadget{
		Nullifiers:      make([]frontend.Variable, nullifierSize),
		Commitments:     make([]frontend.Variable, commitmentSize),
		OwnerMemoHashes: make([]frontend.Variable, commitmentSize),
		AuditMemoHashes: make([]frontend.Variable, commitmentSize),
	}
}

func (gadget *UTXOGadget) BuildAndCheck(api frontend.API) (*UTXOResultGadget, error) {
	nullifiers := make([]frontend.Variable, len(gadget.Nullifier))
	commitments := make([]frontend.Variable, len(gadget.Commitment))

	// Check that the number of nullifiers, commitments, and ephemeral secret keys are the same
	if len(gadget.Commitment) != len(gadget.EphemeralReceiverSecretKey) || len(gadget.Commitment) != len(gadget.EphemeralAuditSecretKey) {
		return nil, fmt.Errorf("number of nullifiers, commitments, and ephemeral receiver and audit secret keys must be the same")
	}

	inputAmounts := make([]frontend.Variable, len(gadget.AllAsset))

	for i := range gadget.AllAsset {
		inputAmounts[i] = 0
	}

	for i := range gadget.Nullifier {
		gadgetNullifier := gadget.Nullifier[i]

		rangerChecker := rangecheck.New(api)
		rangerChecker.Check(gadgetNullifier.Amount, 253)

		// TODO: Check nullifier is in merkle tree

		for j := range gadget.AllAsset {
			diff := api.Sub(gadget.AllAsset[j], gadgetNullifier.Asset)
			isZero := api.IsZero(diff)
			inputAmounts[j] = api.Add(inputAmounts[j], api.Mul(gadgetNullifier.Amount, isZero))
		}

		nullifier, err := gadgetNullifier.Compute(api)
		if err != nil {
			return nil, fmt.Errorf("failed to compute nullifier: %w", err)
		}
		nullifiers[i] = nullifier
	}

	ownerMemoHashes := make([]frontend.Variable, len(gadget.EphemeralReceiverSecretKey))
	auditMemoHashes := make([]frontend.Variable, len(gadget.EphemeralAuditSecretKey))

	outputAmounts := make([]frontend.Variable, len(gadget.AllAsset))

	for i := range gadget.AllAsset {
		outputAmounts[i] = 0
	}

	for i := range gadget.Commitment {
		gadgetCommitment := gadget.Commitment[i]

		rangerChecker := rangecheck.New(api)
		rangerChecker.Check(gadgetCommitment.Amount, 253)

		for j := range gadget.AllAsset {
			diff := api.Sub(gadget.AllAsset[j], gadgetCommitment.Asset)
			isZero := api.IsZero(diff)
			outputAmounts[j] = api.Add(outputAmounts[j], api.Mul(gadgetCommitment.Amount, isZero))
		}

		commitment, err := gadgetCommitment.Compute(api)
		if err != nil {
			return nil, fmt.Errorf("failed to compute commitment: %w", err)
		}
		commitments[i] = commitment

		ownerMemoGadget := MemoGadget{
			EphemeralSecretKey: gadget.EphemeralReceiverSecretKey[i],
			ReceiverPublicKey:  gadget.ReceiverPublicKey,
		}

		ownerMemoHash, err := ownerMemoGadget.Generate(api, gadgetCommitment)
		if err != nil {
			return nil, fmt.Errorf("failed to generate owner memo: %w", err)
		}
		ownerMemoHashes[i] = ownerMemoHash

		auditMemoGadget := MemoGadget{
			EphemeralSecretKey: gadget.EphemeralAuditSecretKey[i],
			ReceiverPublicKey:  gadget.AuditPublicKey,
		}

		auditMemoHash, err := auditMemoGadget.Generate(api, gadgetCommitment)
		if err != nil {
			return nil, fmt.Errorf("failed to generate audit memo: %w", err)
		}
		auditMemoHashes[i] = auditMemoHash
	}

	for i := range inputAmounts {
		api.AssertIsEqual(inputAmounts[i], outputAmounts[i])
	}

	return &UTXOResultGadget{
		Nullifiers:      nullifiers,
		Commitments:     commitments,
		OwnerMemoHashes: ownerMemoHashes,
		AuditMemoHashes: auditMemoHashes,
	}, nil
}

type UTXOCircuit struct {
	UTXOGadget
	UTXOResultGadget
}

func NewUTXOCircuit(allAssetSize int, nullifierSize int, commitmentSize int) *UTXOCircuit {
	return &UTXOCircuit{
		UTXOGadget:       *NewUTXOGadget(allAssetSize, nullifierSize, commitmentSize),
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

	return nil
}
