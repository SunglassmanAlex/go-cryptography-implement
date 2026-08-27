package iknp

func getBit(data []byte, i int) byte {
	byteIdx := i / 8
	bitIdx := uint(i % 8)
	return (data[byteIdx] >> bitIdx) & 1
}

func setBit(data []byte, i int, v byte) {
	byteIdx := i / 8
	bitIdx := uint(i % 8)
	data[byteIdx] &^= 1 << bitIdx
	data[byteIdx] |= (v & 1) << bitIdx
}

func transposeBits(rows [][]byte, bitLen int) [][]byte {
	cols := make([][]byte, bitLen)
	byteLen := (len(rows) + 7) / 8
	for i := 0; i < bitLen; i++ {
		cols[i] = make([]byte, byteLen)
		for j := 0; j < len(rows); j++ {
			setBit(cols[i], j, getBit(rows[j], i))
		}
	}
	return cols
}

func packBits(bits []byte) []byte {
	out := make([]byte, (len(bits)+7)/8)
	for i, b := range bits {
		if b&1 == 1 {
			setBit(out, i, 1)
		}
	}
	return out
}

func applyChoiceCorrection(tCol, uCol, s []byte, choice byte) []byte {
	out := make([]byte, len(tCol))
	for j := 0; j < len(tCol)*8; j++ {
		tBit := getBit(tCol, j)
		uBit := getBit(uCol, j)
		sBit := getBit(s, j)

		var bit byte
		if choice == 0 {
			bit = tBit ^ (sBit & uBit)
		} else {
			bit = tBit ^ ((sBit ^ 1) & uBit)
		}
		setBit(out, j, bit)
	}
	return out
}
