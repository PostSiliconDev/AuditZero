package circuits

import "github.com/consensys/gnark/frontend"

type MemoCircuit struct {
	Output frontend.Variable `gnark:"output"`

	EphemeralSecretKey frontend.Variable `gnark:"ephemeralSecretKey"`

	ReceiverPublicKeyX frontend.Variable `gnark:"receiverPublicKeyX"`
	ReceiverPublicKeyY frontend.Variable `gnark:"receiverPublicKeyY"`

	EncryptedHash frontend.Variable `gnark:"encryptedHash,public"`
}

func NewMemoCircuit() *MemoCircuit {
	return &MemoCircuit{}
}

func (circuit *MemoCircuit) Define(api frontend.API) error {
	ecdh := ECDHCircuit{}
	ecdh.Define(api)

	return nil
}
