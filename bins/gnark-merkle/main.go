package main

func main() {

	// witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	// if err != nil {
	// 	panic(fmt.Sprintf("failed to create witness: %v", err))
	// }

	// publicWitness, err := witness.Public()
	// if err != nil {
	// 	panic(fmt.Sprintf("failed to create public witness: %v", err))
	// }

	// cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	// if err != nil {
	// 	panic(fmt.Sprintf("failed to compile circuit: %v", err))
	// }

	// pk, vk, err := groth16.Setup(cs)
	// if err != nil {
	// 	panic(fmt.Sprintf("failed to setup circuit: %v", err))
	// }

	// proof, err := groth16.Prove(cs, pk, witness)
	// if err != nil {
	// 	panic(fmt.Sprintf("failed to prove circuit: %v", err))
	// }

	// err = groth16.Verify(proof, vk, publicWitness)
	// if err != nil {
	// 	panic(fmt.Sprintf("failed to verify circuit: %v", err))
	// } else {
	// 	fmt.Println("Proof verified")
	// }
}
