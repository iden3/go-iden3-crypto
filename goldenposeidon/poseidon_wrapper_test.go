package poseidon

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func u64SliceToByteSlice(input []uint64) []byte {
	inputBytes := bytes.NewBuffer(nil)
	for _, num := range input {
		_ = binary.Write(inputBytes, binary.BigEndian, num)
	}
	return inputBytes.Bytes()
}

func TestPoseidonWrapperSum(t *testing.T) {
	for i, vector := range testVectors {
		t.Run(fmt.Sprintf("test vector %d", i), func(t *testing.T) {
			var inputVector [NROUNDSF + CAPLEN]uint64
			copy(inputVector[:NROUNDSF], vector.bytes.inpBi[:])
			copy(inputVector[NROUNDSF:], vector.bytes.capBi[:])

			hasher, err := New()
			require.NoError(t, err)
			hasher.Write(u64SliceToByteSlice(inputVector[:]))
			res := hasher.Sum(nil)

			require.NotEmpty(t, res)
			require.Equal(t, u64SliceToByteSlice(vector.expectedHash[:]), res)
		})
	}
}

func TestPoseidonNewPoseidon(t *testing.T) {
	for i, vector := range testVectors {
		t.Run(fmt.Sprintf("test vector %d", i), func(t *testing.T) {
			var inputVector [NROUNDSF + CAPLEN]uint64
			copy(inputVector[:NROUNDSF], vector.bytes.inpBi[:])
			copy(inputVector[NROUNDSF:], vector.bytes.capBi[:])

			res := Sum(u64SliceToByteSlice(inputVector[:]))
			require.NotEmpty(t, res)
			require.Equal(t, u64SliceToByteSlice(vector.expectedHash[:]), res)
		})
	}
}
