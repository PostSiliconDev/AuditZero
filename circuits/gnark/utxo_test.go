package circuits_test

import (
	circuits "hide-pay/circuits/gnark"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/test"
	"github.com/stretchr/testify/assert"
)

func TestUTXO_BuildAndCheck(t *testing.T) {
	receiverSecretKey := big.NewInt(11111)
	auditSecretKey := big.NewInt(22222)

	receiverPublicKey := buildPublicKey(*receiverSecretKey)
	auditPublicKey := buildPublicKey(*auditSecretKey)

	nullifier1 := circuits.Nullifier{
		Commitment: circuits.Commitment{
			Asset:    fr.NewElement(1),
			Amount:   fr.NewElement(2),
			Blinding: fr.NewElement(3),
		},
		PrivateKey: fr.NewElement(1),
	}

	nullifier2 := circuits.Nullifier{
		Commitment: circuits.Commitment{
			Asset:    fr.NewElement(1),
			Amount:   fr.NewElement(2),
			Blinding: fr.NewElement(4),
		},
		PrivateKey: fr.NewElement(2),
	}

	utxo := &circuits.UTXO{
		Nullifier: []circuits.Nullifier{
			nullifier1,
			nullifier2,
		},
		Commitment: []circuits.Commitment{
			{
				Asset:    fr.NewElement(1),
				Amount:   fr.NewElement(2),
				Blinding: fr.NewElement(3),
			},
			{
				Asset:    fr.NewElement(1),
				Amount:   fr.NewElement(2),
				Blinding: fr.NewElement(3),
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

	for i := range result.Commitments {
		commitment := result.Commitments[i]

		memo1 := circuits.Memo{
			SecretKey: *receiverSecretKey,
			PublicKey: commitment.OwnerEphemeralPublickKey,
		}

		ownerMemoCiphertext := []fr.Element{
			commitment.OwnerMemo[0],
			commitment.OwnerMemo[1],
			commitment.OwnerMemo[2],
			commitment.OwnerHMAC,
		}

		decryptedOwnerMemo, err := memo1.Decrypt(ownerMemoCiphertext)
		assert.NoError(t, err)
		assert.Equal(t, decryptedOwnerMemo.Asset, utxo.Commitment[i].Asset)
		assert.Equal(t, decryptedOwnerMemo.Amount, utxo.Commitment[i].Amount)
		assert.Equal(t, decryptedOwnerMemo.Blinding, utxo.Commitment[i].Blinding)

		memo2 := circuits.Memo{
			SecretKey: *auditSecretKey,
			PublicKey: commitment.AuditEphemeralPublickKey,
		}

		auditMemoCiphertext := []fr.Element{
			commitment.AuditMemo[0],
			commitment.AuditMemo[1],
			commitment.AuditMemo[2],
			commitment.AuditHMAC,
		}

		decryptedAuditMemo, err := memo2.Decrypt(auditMemoCiphertext)
		assert.NoError(t, err)
		assert.Equal(t, decryptedAuditMemo.Asset, utxo.Commitment[i].Asset)
		assert.Equal(t, decryptedAuditMemo.Amount, utxo.Commitment[i].Amount)
		assert.Equal(t, decryptedAuditMemo.Blinding, utxo.Commitment[i].Blinding)
	}
}

func TestUTXO_ToGadget(t *testing.T) {
	receiverSecretKey := big.NewInt(11111)
	auditSecretKey := big.NewInt(22222)

	receiverPublicKey := buildPublicKey(*receiverSecretKey)
	auditPublicKey := buildPublicKey(*auditSecretKey)

	utxo := &circuits.UTXO{
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

	witness, err := circuits.NewUTXOCircuitWitness(utxo, result)
	assert.NoError(t, err)

	utxoCircuit := circuits.NewUTXOCircuit(len(result.AllAsset), len(utxo.Nullifier), len(utxo.Commitment))

	assert := test.NewAssert(t)

	assert.ProverSucceeded(utxoCircuit, witness, test.WithCurves(ecc.BN254))
}
