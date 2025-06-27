package circuits_test

import (
	"hide-pay/builder"
	"hide-pay/circuits"
	"hide-pay/utils"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/test"
	"github.com/stretchr/testify/assert"
)

func TestUTXO_ToGadget(t *testing.T) {
	receiverSecretKey := big.NewInt(11111)
	auditSecretKey := big.NewInt(22222)

	receiverPublicKey := utils.BuildPublicKey(*receiverSecretKey)
	auditPublicKey := utils.BuildPublicKey(*auditSecretKey)

	utxo := &builder.UTXO{
		Nullifier: []circuits.Nullifier{
			{
				Commitment: circuits.Commitment{
					Asset:    fr.NewElement(1),
					Amount:   fr.NewElement(2),
					Blinding: fr.NewElement(3),
				},
				PrivateKey: fr.NewElement(1),
			},
			{
				Commitment: circuits.Commitment{
					Asset:    fr.NewElement(1),
					Amount:   fr.NewElement(2),
					Blinding: fr.NewElement(4),
				},
				PrivateKey: fr.NewElement(2),
			},
		},
		Commitment: []circuits.Commitment{
			{
				Asset:    fr.NewElement(1),
				Amount:   fr.NewElement(2),
				Blinding: fr.NewElement(5),
			},
			{
				Asset:    fr.NewElement(1),
				Amount:   fr.NewElement(2),
				Blinding: fr.NewElement(6),
			},
		},
		EphemeralReceiverSecretKey: []big.Int{
			*big.NewInt(1),
			*big.NewInt(2),
		},
		EphemeralAuditSecretKey: []big.Int{
			*big.NewInt(3),
			*big.NewInt(4),
		},
		ReceiverPublicKey: receiverPublicKey,
		AuditPublicKey:    auditPublicKey,
	}

	result, err := utxo.BuildAndCheck()
	assert.NoError(t, err)

	witness, err := builder.NewUTXOCircuitWitness(utxo, result)
	assert.NoError(t, err)

	utxoCircuit := circuits.NewUTXOCircuit(len(result.AllAsset), len(utxo.Nullifier), len(utxo.Commitment))

	assert := test.NewAssert(t)

	assert.ProverSucceeded(utxoCircuit, witness, test.WithCurves(ecc.BN254))
}
