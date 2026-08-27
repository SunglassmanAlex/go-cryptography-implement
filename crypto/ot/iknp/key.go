package iknp

import "crypto/sha256"

func keyFromColumn(col []byte) []byte {
	h := sha256.Sum256(col)
	return h[:]
}
