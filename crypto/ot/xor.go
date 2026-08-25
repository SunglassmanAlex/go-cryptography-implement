package ot

func XorBytes(msg, key []byte) []byte {
	out := make([]byte, len(msg))
	for i := range msg {
		out[i] = msg[i] ^ key[i%len(key)]
	}
	return out
}
