package iknp

import "crypto/rand"

const SeedSize = 16

func randomSeed() ([]byte, error) {
	seed := make([]byte, SeedSize)
	_, err := rand.Read(seed)
	if err != nil {
		return nil, err
	}
	return seed, nil
}

func randomBit() (byte, error) {
	var b [1]byte
	_, err := rand.Read(b[:])
	if err != nil {
		return 0, err
	}
	return b[0] & 1, nil
}

func randomBytes(n int) ([]byte, error) {
	out := make([]byte, n)
	_, err := rand.Read(out)
	if err != nil {
		return nil, err
	}
	return out, nil
}
