package circuits

import "github.com/consensys/gnark/frontend"

type OutputCircuit struct {
	Asset    frontend.Variable `gnark:"asset"`
	Amount   frontend.Variable `gnark:"amount"`
	Blinding frontend.Variable `gnark:"blinding"`
}
