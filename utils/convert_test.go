package utils_test

import (
	"hide-pay/utils"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIntToBits(t *testing.T) {
	bits := utils.IntToBits(6, 4)

	for i := 0; i < len(bits); i++ {
		assert.Equal(t, bits[i], (6>>i)&1 != 0)
	}
}
