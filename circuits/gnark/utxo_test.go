package circuits_test

import (
	circuits "hide-pay/circuits/gnark"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/stretchr/testify/require"
)

func TestUTXO_BuildAndCheck(t *testing.T) {
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
				Blinding: fr.NewElement(3),
			},
		},
		EphemeralReceiverSecretKey: []big.Int{
			*big.NewInt(1),
		},
		EphemeralAuditSecretKey: []big.Int{
			*big.NewInt(2),
		},
		ReceiverPublicKey: receiverPublicKey,
		AuditPublicKey:    auditPublicKey,
	}

	result, err := utxo.BuildAndCheck()
	require.NoError(t, err)

	for i := 0; i < len(result.Commitments); i++ {
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
		require.NoError(t, err)
		require.Equal(t, decryptedOwnerMemo.Asset, utxo.Commitment[i].Asset)
		require.Equal(t, decryptedOwnerMemo.Amount, utxo.Commitment[i].Amount)
		require.Equal(t, decryptedOwnerMemo.Blinding, utxo.Commitment[i].Blinding)

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
		require.NoError(t, err)
		require.Equal(t, decryptedAuditMemo.Asset, utxo.Commitment[i].Asset)
		require.Equal(t, decryptedAuditMemo.Amount, utxo.Commitment[i].Amount)
		require.Equal(t, decryptedAuditMemo.Blinding, utxo.Commitment[i].Blinding)
	}
}

func TestUTXO_ToGadget(t *testing.T) {}
