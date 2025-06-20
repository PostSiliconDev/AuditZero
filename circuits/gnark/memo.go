package circuits

import "github.com/consensys/gnark/frontend"

type MemoCircuit struct {
	Output frontend.Variable `gnark:"output"`

	EphemeralSecretKey frontend.Variable `gnark:"ephemeralSecretKey"`

	ReceiverPublicKey [2]frontend.Variable `gnark:"receiverPublicKey"`
}

func NewMemoCircuit() *MemoCircuit {
	return &MemoCircuit{}
}

func (circuit *MemoCircuit) Define(api frontend.API) error {

	return nil
}
