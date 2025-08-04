package circuits_test

import (
	"hide-pay/builder"
	"hide-pay/circuits"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type SchnorrCircuit struct {
	circuits.SchnorrGadget
}

func NewSchnorrCircuit() *SchnorrCircuit {
	return &SchnorrCircuit{}
}

func (circuit *SchnorrCircuit) Define(api frontend.API) error {
	err := circuit.SchnorrGadget.VerifySignature(api)
	if err != nil {
		return err
	}

	return nil
}

func TestSchnorr_Circuit_Verification(t *testing.T) {
	privateKey := fr.NewElement(12345)
	random := fr.NewElement(12345)

	kp, err := builder.GenerateKeypairWithSeed(privateKey)
	require.NoError(t, err)

	messageHash := fr.NewElement(12345)
	signature := kp.Sign(random, messageHash)

	result := builder.Verify(messageHash, signature, &kp.PublicKey)
	assert.True(t, result)

	circuit := NewSchnorrCircuit()
	assert.NotNil(t, circuit)

	assert := test.NewAssert(t)

	witness := SchnorrCircuit{
		SchnorrGadget: *circuits.NewSchnorrGadget(messageHash, signature.S, [2]frontend.Variable{signature.R.X, signature.R.Y}, [2]frontend.Variable{kp.PublicKey.X, kp.PublicKey.Y}),
	}

	options := test.WithCurves(ecc.BN254)
	assert.ProverSucceeded(circuit, &witness, options)
}
