package iknp

import (
	"crypto/sha256"
	"encoding/binary"
)

func expandSeed(seed []byte, outLen int) ([]byte, error) {
	out := make([]byte, 0, outLen)

	var counter uint32 = 0

	for len(out) < outLen {
		h := sha256.New()
		h.Write(seed)

		var c [4]byte
		binary.BigEndian.PutUint32(c[:], counter)
		h.Write(c[:])

		block := h.Sum(nil)
		need := outLen - len(out)

		if need > len(block) {
			need = len(block)
		}
		out = append(out, block[:need]...)
		counter++
	}

	return out, nil
}

func expandSeeds(seeds [][]byte, outLen int) ([][]byte, error) {
	out := make([][]byte, len(seeds))
	for j, seed := range seeds {
		expanded, err := expandSeed(seed, outLen)
		if err != nil {
			return nil, err
		}
		out[j] = expanded
	}
	return out, nil
}
