package circuits

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	twistededwardbn254 "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"github.com/consensys/gnark/frontend"
)

type UTXOGadget struct {
	Nullifier          []NullifierGadget   `gnark:"nullifier"`
	Commitment         []CommitmentGadget  `gnark:"commitment"`
	EphemeralSecretKey []frontend.Variable `gnark:"ephemeralSecretKey"`

	ReceiverPublicKey [2]frontend.Variable `gnark:"receiverPublicKey"`
	AuditPublicKey    [2]frontend.Variable `gnark:"auditPublicKey"`
}

type UTXOResultGadget struct {
	Nullifiers  []frontend.Variable `gnark:"nullifier"`
	Commitments []frontend.Variable `gnark:"commitment"`
	OwnerMemos  []frontend.Variable `gnark:"ownerMemo"`
	AuditMemos  []frontend.Variable `gnark:"auditMemo"`
}

func (gadget *UTXOGadget) BuildAndCheck(api frontend.API) (*UTXOResultGadget, error) {
	nullifiers := make([]frontend.Variable, len(gadget.Nullifier))
	commitments := make([]frontend.Variable, len(gadget.Commitment))

	// Check that the number of nullifiers, commitments, and ephemeral secret keys are the same
	if len(gadget.Commitment) != len(gadget.EphemeralSecretKey) {
		return nil, fmt.Errorf("number of nullifiers, commitments, and ephemeral secret keys must be the same")
	}

	// Check balance of left and right side of the UTXO

	for i := range gadget.Nullifier {
		nullifier, err := gadget.Nullifier[i].Compute(api)
		if err != nil {
			return nil, fmt.Errorf("failed to compute nullifier: %w", err)
		}
		nullifiers[i] = nullifier
	}

	ownerMemos := make([]frontend.Variable, len(gadget.EphemeralSecretKey)*4)
	auditMemos := make([]frontend.Variable, len(gadget.EphemeralSecretKey)*4)

	for i := range gadget.Commitment {
		commitment, err := gadget.Commitment[i].Compute(api)
		if err != nil {
			return nil, fmt.Errorf("failed to compute commitment: %w", err)
		}
		commitments[i] = commitment

		ownerMemoGadget := MemoGadget{
			EphemeralSecretKey: gadget.EphemeralSecretKey[i],
			ReceiverPublicKey:  gadget.ReceiverPublicKey,
		}

		ownerMemo, err := ownerMemoGadget.Generate(api, gadget.Commitment[i])
		if err != nil {
			return nil, fmt.Errorf("failed to generate owner memo: %w", err)
		}
		ownerMemos[i*4] = ownerMemo

		auditMemoGadget := MemoGadget{
			EphemeralSecretKey: gadget.EphemeralSecretKey[i],
			ReceiverPublicKey:  gadget.AuditPublicKey,
		}

		auditMemo, err := auditMemoGadget.Generate(api, gadget.Commitment[i])
		if err != nil {
			return nil, fmt.Errorf("failed to generate audit memo: %w", err)
		}
		auditMemos[i*4] = auditMemo
	}

	return &UTXOResultGadget{
		Nullifiers:  nullifiers,
		Commitments: commitments,
		OwnerMemos:  ownerMemos,
		AuditMemos:  auditMemos,
	}, nil
}

type UTXO struct {
	Nullifier          []Nullifier
	Commitment         []Commitment
	EphemeralSecretKey []big.Int

	ReceiverPublicKey [2]fr.Element
	AuditPublicKey    [2]fr.Element
}

type UTXOResult struct {
	Nullifiers    []fr.Element
	Commitments   []fr.Element
	OwnerMemos    []fr.Element
	OwnerMemoHMAC fr.Element
	AuditMemos    []fr.Element
	AuditMemoHMAC fr.Element
}

func (utxo *UTXO) BuildAndCheck() (*UTXOResult, error) {
	nullifiers := make([]fr.Element, len(utxo.Nullifier))
	commitments := make([]fr.Element, len(utxo.Commitment))

	for i := range utxo.Nullifier {
		nullifiers[i] = utxo.Nullifier[i].Compute()
	}

	// Check balance of left and right side of the UTXO

	ownerMemos := make([]fr.Element, len(utxo.EphemeralSecretKey)*4)
	auditMemos := make([]fr.Element, len(utxo.EphemeralSecretKey)*4)

	result := UTXOResult{
		Nullifiers:    nullifiers,
		Commitments:   commitments,
		OwnerMemos:    ownerMemos,
		OwnerMemoHMAC: fr.Element{},
		AuditMemos:    auditMemos,
		AuditMemoHMAC: fr.Element{},
	}

	for i := range utxo.Commitment {
		commitments[i] = utxo.Commitment[i].Compute()

		ownerMemo := Memo{
			SecretKey: utxo.EphemeralSecretKey[i],
			PublicKey: twistededwardbn254.PointAffine{
				X: utxo.ReceiverPublicKey[0],
				Y: utxo.ReceiverPublicKey[1],
			},
		}

		ownerMemoCiphertext, err := ownerMemo.Encrypt(utxo.Commitment[i])
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt owner memo: %w", err)
		} else {
			ownerMemos[i*4] = ownerMemoCiphertext[0]
			ownerMemos[i*4+1] = ownerMemoCiphertext[1]
			ownerMemos[i*4+2] = ownerMemoCiphertext[2]
			result.OwnerMemoHMAC = ownerMemoCiphertext[3]
		}

		auditMemo := Memo{
			SecretKey: utxo.EphemeralSecretKey[i],
			PublicKey: twistededwardbn254.PointAffine{
				X: utxo.AuditPublicKey[0],
				Y: utxo.AuditPublicKey[1],
			},
		}

		auditMemoCiphertext, err := auditMemo.Encrypt(utxo.Commitment[i])
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt audit memo: %w", err)
		}

		auditMemos[i*4] = auditMemoCiphertext[0]
		auditMemos[i*4+1] = auditMemoCiphertext[1]
		auditMemos[i*4+2] = auditMemoCiphertext[2]
		result.AuditMemoHMAC = auditMemoCiphertext[3]
	}

	return &result, nil
}
