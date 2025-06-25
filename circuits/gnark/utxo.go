package circuits

import (
	"fmt"
	"math/big"
	"reflect"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	twistededwardbn254 "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/rangecheck"
)

type UTXOGadget struct {
	AllAsset []frontend.Variable `gnark:"allAsset"`

	Nullifier                  []NullifierGadget   `gnark:"nullifier"`
	Commitment                 []CommitmentGadget  `gnark:"commitment"`
	EphemeralReceiverSecretKey []frontend.Variable `gnark:"ephemeralReceiverSecretKey"`
	EphemeralAuditSecretKey    []frontend.Variable `gnark:"ephemeralAuditSecretKey"`

	ReceiverPublicKey [2]frontend.Variable `gnark:"receiverPublicKey"`
	AuditPublicKey    [2]frontend.Variable `gnark:"auditPublicKey"`
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

	// api.AssertIsEqual(inputAmount, outputAmount)

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

func NewUTXOCircuitWitness(utxo *UTXO, utxoResult *UTXOResult) *UTXOCircuit {
	allAsset := make([]frontend.Variable, len(utxoResult.AllAsset))

	for i := range utxoResult.AllAsset {
		allAsset[i] = utxoResult.AllAsset[i]
	}

	return &UTXOCircuit{
		UTXOGadget:       *utxo.ToGadget(allAsset),
		UTXOResultGadget: *utxoResult.ToGadget(),
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

type UTXO struct {
	Nullifier                  []Nullifier
	Commitment                 []Commitment
	EphemeralReceiverSecretKey []big.Int
	EphemeralAuditSecretKey    []big.Int

	ReceiverPublicKey twistededwardbn254.PointAffine
	AuditPublicKey    twistededwardbn254.PointAffine
}

func (utxo *UTXO) ToGadget(allAsset []frontend.Variable) *UTXOGadget {
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

	for i := range utxo.EphemeralAuditSecretKey {
		ephemeralAuditSecretKeys[i] = utxo.EphemeralAuditSecretKey[i]
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
		AllAsset:                   allAsset,
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
	AllAsset    []fr.Element
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
	allAsset := make([]frontend.Variable, len(result.AllAsset))

	for i := range result.Nullifiers {
		nullifiers[i] = result.Nullifiers[i]
	}

	for i := range result.Commitments {
		commitments[i] = result.Commitments[i].Commitment
		ownerMemoHashes[i] = result.Commitments[i].OwnerHMAC
		auditMemoHashes[i] = result.Commitments[i].AuditHMAC
	}

	for i := range result.AllAsset {
		allAsset[i] = result.AllAsset[i]
	}

	return &UTXOResultGadget{
		Nullifiers:      nullifiers,
		Commitments:     commitments,
		OwnerMemoHashes: ownerMemoHashes,
		AuditMemoHashes: auditMemoHashes,
	}
}

func addToAssetMapping(assetMapping map[fr.Element]*fr.Element, asset fr.Element, amount fr.Element) {
	if _, ok := assetMapping[asset]; !ok {
		assetMapping[asset] = &amount
	} else {
		assetMapping[asset].Add(assetMapping[asset], &amount)
	}
}

func (utxo *UTXO) BuildAndCheck() (*UTXOResult, error) {
	nullifiers := make([]fr.Element, len(utxo.Nullifier))
	commitments := make([]UTXOCommitment, len(utxo.Commitment))

	allAssetInput := make(map[fr.Element]*fr.Element)

	for i := range utxo.Nullifier {
		utxoNullifier := utxo.Nullifier[i]

		zero := fr.NewElement(0)
		if utxoNullifier.Amount.Cmp(&zero) != 1 {
			return nil, fmt.Errorf("nullifier must be greater than 0")
		}

		addToAssetMapping(allAssetInput, utxoNullifier.Asset, utxoNullifier.Amount)

		nullifiers[i] = utxoNullifier.Compute()
	}

	fmt.Println("allAssetInput", allAssetInput)

	// Check balance of left and right side of the UTXO

	result := UTXOResult{
		Nullifiers:  nullifiers,
		Commitments: commitments,
		AllAsset:    make([]fr.Element, len(allAssetInput)),
	}

	allAssetOutput := make(map[fr.Element]*fr.Element)

	for i := range utxo.Commitment {
		utxoCommitment := utxo.Commitment[i]

		zero := fr.NewElement(0)
		if utxoCommitment.Amount.Cmp(&zero) != 1 {
			return nil, fmt.Errorf("commitment must be greater than 0")
		}

		addToAssetMapping(allAssetOutput, utxoCommitment.Asset, utxoCommitment.Amount)

		commitment := utxoCommitment.Compute()

		ownerMemo := Memo{
			SecretKey: utxo.EphemeralReceiverSecretKey[i],
			PublicKey: utxo.ReceiverPublicKey,
		}

		ownerMemoEphemeralPublickKey, ownerMemoCiphertext, err := ownerMemo.Encrypt(utxoCommitment)
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

		auditMemoEphemeralPublickKey, auditMemoCiphertext, err := auditMemo.Encrypt(utxoCommitment)
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

	if !reflect.DeepEqual(allAssetInput, allAssetOutput) {
		return nil, fmt.Errorf("input and output asset mapping must be the same")
	}

	for asset := range allAssetInput {
		result.AllAsset = append(result.AllAsset, asset)
	}

	return &result, nil
}
