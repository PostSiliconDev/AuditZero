package circuits

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	twistededwardbn254 "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"github.com/consensys/gnark/frontend"
)

type UTXOGadget struct {
	Nullifier                  []NullifierGadget   `gnark:"nullifier"`
	Commitment                 []CommitmentGadget  `gnark:"commitment"`
	EphemeralReceiverSecretKey []frontend.Variable `gnark:"ephemeralReceiverSecretKey"`
	EphemeralAuditSecretKey    []frontend.Variable `gnark:"ephemeralAuditSecretKey"`

	ReceiverPublicKey [2]frontend.Variable `gnark:"receiverPublicKey"`
	AuditPublicKey    [2]frontend.Variable `gnark:"auditPublicKey"`
}

type UTXOResultGadget struct {
	Nullifiers      []frontend.Variable `gnark:"nullifiers,public"`
	Commitments     []frontend.Variable `gnark:"commitments,public"`
	OwnerMemoHashes []frontend.Variable `gnark:"ownerMemoHashes,public"`
	AuditMemoHashes []frontend.Variable `gnark:"auditMemoHashes,public"`
}

func (gadget *UTXOGadget) BuildAndCheck(api frontend.API) (*UTXOResultGadget, error) {
	nullifiers := make([]frontend.Variable, len(gadget.Nullifier))
	commitments := make([]frontend.Variable, len(gadget.Commitment))

	// Check that the number of nullifiers, commitments, and ephemeral secret keys are the same
	if len(gadget.Commitment) != len(gadget.EphemeralReceiverSecretKey) || len(gadget.Commitment) != len(gadget.EphemeralAuditSecretKey) {
		return nil, fmt.Errorf("number of nullifiers, commitments, and ephemeral receiver and audit secret keys must be the same")
	}

	// Check balance of left and right side of the UTXO

	for i := range gadget.Nullifier {
		nullifier, err := gadget.Nullifier[i].Compute(api)
		if err != nil {
			return nil, fmt.Errorf("failed to compute nullifier: %w", err)
		}
		nullifiers[i] = nullifier
	}

	ownerMemoHashes := make([]frontend.Variable, len(gadget.EphemeralReceiverSecretKey))
	auditMemoHashes := make([]frontend.Variable, len(gadget.EphemeralAuditSecretKey))

	for i := range gadget.Commitment {
		commitment, err := gadget.Commitment[i].Compute(api)
		if err != nil {
			return nil, fmt.Errorf("failed to compute commitment: %w", err)
		}
		commitments[i] = commitment

		ownerMemoGadget := MemoGadget{
			EphemeralSecretKey: gadget.EphemeralReceiverSecretKey[i],
			ReceiverPublicKey:  gadget.ReceiverPublicKey,
		}

		ownerMemoHash, err := ownerMemoGadget.Generate(api, gadget.Commitment[i])
		if err != nil {
			return nil, fmt.Errorf("failed to generate owner memo: %w", err)
		}
		ownerMemoHashes[i] = ownerMemoHash

		auditMemoGadget := MemoGadget{
			EphemeralSecretKey: gadget.EphemeralAuditSecretKey[i],
			ReceiverPublicKey:  gadget.AuditPublicKey,
		}

		auditMemoHash, err := auditMemoGadget.Generate(api, gadget.Commitment[i])
		if err != nil {
			return nil, fmt.Errorf("failed to generate audit memo: %w", err)
		}
		auditMemoHashes[i] = auditMemoHash
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

func (circuit *UTXOCircuit) Define(api frontend.API) error {
	utxoResult, err := circuit.UTXOGadget.BuildAndCheck(api)
	if err != nil {
		return fmt.Errorf("failed to build and check UTXO: %w", err)
	}

	api.AssertIsEqual(circuit.UTXOResultGadget.Nullifiers, utxoResult.Nullifiers)
	api.AssertIsEqual(circuit.UTXOResultGadget.Commitments, utxoResult.Commitments)
	api.AssertIsEqual(circuit.UTXOResultGadget.OwnerMemoHashes, utxoResult.OwnerMemoHashes)
	api.AssertIsEqual(circuit.UTXOResultGadget.AuditMemoHashes, utxoResult.AuditMemoHashes)

	return nil
}

type UTXO struct {
	Nullifier                  []Nullifier
	Commitment                 []Commitment
	EphemeralReceiverSecretKey []big.Int
	EphemeralAuditSecretKey    []big.Int

	ReceiverPublicKey twistededwardbn254.PointAffine
	AuditPublicKey    twistededwardbn254.PointAffine
}

func (utxo *UTXO) ToGadget() *UTXOGadget {
	nullifiers := make([]NullifierGadget, len(utxo.Nullifier))
	commitments := make([]CommitmentGadget, len(utxo.Commitment))

	for i := range utxo.Nullifier {
		nullifiers[i] = *utxo.Nullifier[i].ToGadget()
	}

	for i := range utxo.Commitment {
		commitments[i] = *utxo.Commitment[i].ToGadget()
	}

	ephemeralReceiverSecretKeys := make([]frontend.Variable, len(utxo.EphemeralReceiverSecretKey))
	ephemeralAuditSecretKeys := make([]frontend.Variable, len(utxo.EphemeralAuditSecretKey))

	for i := range utxo.EphemeralReceiverSecretKey {
		ephemeralReceiverSecretKeys[i] = utxo.EphemeralReceiverSecretKey[i]
	}

	receiverPublicKey := [2]frontend.Variable{
		utxo.ReceiverPublicKey.X,
		utxo.ReceiverPublicKey.Y,
	}

	auditPublicKey := [2]frontend.Variable{
		utxo.AuditPublicKey.X,
		utxo.AuditPublicKey.Y,
	}

	return &UTXOGadget{
		Nullifier:                  nullifiers,
		Commitment:                 commitments,
		EphemeralReceiverSecretKey: ephemeralReceiverSecretKeys,
		EphemeralAuditSecretKey:    ephemeralAuditSecretKeys,
		ReceiverPublicKey:          receiverPublicKey,
		AuditPublicKey:             auditPublicKey,
	}
}

type UTXOResult struct {
	Nullifiers  []fr.Element
	Commitments []UTXOCommitment
}

type UTXOCommitment struct {
	Commitment               fr.Element
	OwnerMemo                [3]fr.Element
	OwnerHMAC                fr.Element
	OwnerEphemeralPublickKey twistededwardbn254.PointAffine
	AuditMemo                [3]fr.Element
	AuditHMAC                fr.Element
	AuditEphemeralPublickKey twistededwardbn254.PointAffine
}

func (result *UTXOResult) ToGadget() *UTXOResultGadget {
	nullifiers := make([]frontend.Variable, len(result.Nullifiers))
	commitments := make([]frontend.Variable, len(result.Commitments))
	ownerMemoHashes := make([]frontend.Variable, len(result.Commitments))
	auditMemoHashes := make([]frontend.Variable, len(result.Commitments))

	for i := range result.Nullifiers {
		nullifiers[i] = result.Nullifiers[i]
	}

	for i := range result.Commitments {
		commitments[i] = result.Commitments[i].Commitment
		ownerMemoHashes[i] = result.Commitments[i].OwnerMemo
		auditMemoHashes[i] = result.Commitments[i].AuditMemo
	}

	return &UTXOResultGadget{
		Nullifiers:  nullifiers,
		Commitments: commitments,
	}
}

func (utxo *UTXO) BuildAndCheck() (*UTXOResult, error) {
	nullifiers := make([]fr.Element, len(utxo.Nullifier))
	commitments := make([]UTXOCommitment, len(utxo.Commitment))

	for i := range utxo.Nullifier {
		nullifiers[i] = utxo.Nullifier[i].Compute()
	}

	// Check balance of left and right side of the UTXO

	result := UTXOResult{
		Nullifiers:  nullifiers,
		Commitments: commitments,
	}

	for i := range utxo.Commitment {

		commitment := utxo.Commitment[i].Compute()

		ownerMemo := Memo{
			SecretKey: utxo.EphemeralReceiverSecretKey[i],
			PublicKey: utxo.ReceiverPublicKey,
		}

		ownerMemoEphemeralPublickKey, ownerMemoCiphertext, err := ownerMemo.Encrypt(utxo.Commitment[i])
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt owner memo: %w", err)
		}

		ownerMemoData := [3]fr.Element{
			ownerMemoCiphertext[0],
			ownerMemoCiphertext[1],
			ownerMemoCiphertext[2],
		}
		ownerHMAC := ownerMemoCiphertext[3]

		auditMemo := Memo{
			SecretKey: utxo.EphemeralAuditSecretKey[i],
			PublicKey: utxo.AuditPublicKey,
		}

		auditMemoEphemeralPublickKey, auditMemoCiphertext, err := auditMemo.Encrypt(utxo.Commitment[i])
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt audit memo: %w", err)
		}

		auditMemoData := [3]fr.Element{
			auditMemoCiphertext[0],
			auditMemoCiphertext[1],
			auditMemoCiphertext[2],
		}
		auditHMAC := auditMemoCiphertext[3]

		commitments[i] = UTXOCommitment{
			Commitment:               commitment,
			OwnerMemo:                ownerMemoData,
			OwnerHMAC:                ownerHMAC,
			OwnerEphemeralPublickKey: *ownerMemoEphemeralPublickKey,
			AuditMemo:                auditMemoData,
			AuditHMAC:                auditHMAC,
			AuditEphemeralPublickKey: *auditMemoEphemeralPublickKey,
		}
	}

	return &result, nil
}
