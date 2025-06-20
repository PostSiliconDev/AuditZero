package circuits_test

import (
	circuits "hide-pay/circuits/gnark"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/stretchr/testify/require"
)

func TestUTXO_BuildAndCheck(t *testing.T) {
	utxo := &circuits.UTXO{
		Nullifier: []circuits.Nullifier{
			{
				Asset:    fr.NewElement(1),
				Amount:   fr.NewElement(2),
				Blinding: fr.NewElement(3),
			},
		},
		Commitment: []circuits.Commitment{
			{
				Asset:    fr.NewElement(1),
				Amount:   fr.NewElement(2),
				Blinding: fr.NewElement(3),
			},
		},
		EphemeralSecretKey: []big.Int{
			*big.NewInt(1),
		},
		ReceiverPublicKey: [2]fr.Element{
			fr.NewElement(1),
			fr.NewElement(2),
		},
		AuditPublicKey: [2]fr.Element{
			fr.NewElement(3),
			fr.NewElement(4),
		},
	}

	_, err := utxo.BuildAndCheck()
	require.NoError(t, err)
}
