package main

import (
	"github.com/consensys/gnark/frontend"
)

type TestCircuit struct {
	Input0 frontend.Variable `gnark:"input0"`
	Input1 frontend.Variable `gnark:"input1"`
}

func (circuit *TestCircuit) Define(api frontend.API) error {
	sum := api.Add(circuit.Input0, circuit.Input1)
	api.AssertIsEqual(sum, 4)

	return nil
}

func main() {

}
