package circuits

import "github.com/consensys/gnark/frontend"

type OutputGadget struct {
	Asset    frontend.Variable `gnark:"asset"`
	Amount   frontend.Variable `gnark:"amount"`
	Blinding frontend.Variable `gnark:"blinding"`
}
