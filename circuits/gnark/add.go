package circuits

import (
	"github.com/consensys/gnark/frontend"
)

type AddCircuit struct {
	Input1 frontend.Variable
	Input2 frontend.Variable
	Output frontend.Variable
}

func (circuit *AddCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(circuit.Output, api.Add(circuit.Input1, circuit.Input2))
	return nil
}
