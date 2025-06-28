package utils

func IntToBits(n int, bitLen int) []bool {
	bits := make([]bool, bitLen)
	for i := 0; i < bitLen; i++ {
		bits[i] = (n>>i)&1 != 0
	}
	return bits
}
