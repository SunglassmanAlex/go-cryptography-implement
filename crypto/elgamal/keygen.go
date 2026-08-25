package elgamal

import "Implement/crypto/bn254util"

func GenerateKey() (*PrivateKey, *PublicKey, error) {
	x, err := bn254util.RandomNonZeroScalar()
	if err != nil {
		return nil, nil, err
	}
	p := bn254util.PointFromScalar(x)
	priv := &PrivateKey{X: x}
	pub := &PublicKey{Point: p}
	return priv, pub, nil
}

func GeneratePubKey() (*PublicKey, error) {
	x, err := bn254util.RandomNonZeroScalar()
	if err != nil {
		return nil, err
	}
	p := bn254util.PointFromScalar(x)
	pub := &PublicKey{Point: p}
	return pub, nil
}
