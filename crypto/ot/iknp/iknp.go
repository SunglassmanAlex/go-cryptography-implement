package iknp

import (
	"Implement/crypto/ot"
	"Implement/crypto/ot/base"
	"net"
)

const Kappa = 128

func Send(conn net.Conn, m0List, m1List [][]byte) error {
	if len(m0List) != len(m1List) {
		return ErrMessageLengthMismatch
	}

	n := len(m0List)
	byteLen := (n + 7) / 8

	// s 是 Sender 在 base OT 里用的选择比特向量
	s := make([]byte, Kappa)

	// TCols 是 Sender 从 base OT 拿到的 Kappa 列
	tCols := make([][]byte, Kappa)
	for j := 0; j < Kappa; j++ {
		var err error

		s[j], err = randomBit()
		if err != nil {
			return err
		}

		tCols[j], err = base.Receive(conn, s[j])
		if err != nil {
			return err
		}
		if len(tCols[j]) != byteLen {
			return ErrMessageLengthMismatch
		}
	}

	uRows := make([][]byte, Kappa)
	for j := 0; j < Kappa; j++ {
		row, err := ot.ReadBytes(conn)
		if err != nil {
			return err
		}
		uRows[j] = row
	}

	// 把列转成行，方便按 OT 编号 i 逐个取 key
	tRows := transposeBits(tCols, n)
	uCols := transposeBits(uRows, n)
	sBits := packBits(s)

	for i := 0; i < n; i++ {
		// q0 是 Sender 看到的第 i 行
		// q1 由 receiver 发来的修正矩阵 U 和 base OT 选择位 s 混出来
		q0 := tRows[i]
		q1 := applyChoiceCorrection(q0, uCols[i], sBits, 1)

		key0 := keyFromColumn(q0)
		key1 := keyFromColumn(q1)

		cipher0 := ot.XorBytes(m0List[i], key0)
		cipher1 := ot.XorBytes(m1List[i], key1)

		if err := ot.WriteBytes(conn, cipher0); err != nil {
			return err
		}
		if err := ot.WriteBytes(conn, cipher1); err != nil {
			return err
		}
	}

	return nil
}

func Receive(conn net.Conn, choices []byte) ([][]byte, error) {
	n := len(choices)
	byteLen := (n + 7) / 8
	choiceBits := packBits(choices)

	// Q0Cols / Q1Cols 是 Receiver 在 base OT 里生成并发送给 Sender 的两组列
	q0Cols := make([][]byte, Kappa)
	q1Cols := make([][]byte, Kappa)
	uRows := make([][]byte, Kappa)
	for j := 0; j < Kappa; j++ {
		var err error

		q0Cols[j], err = randomBytes(byteLen)
		if err != nil {
			return nil, err
		}
		q1Cols[j] = ot.XorBytes(q0Cols[j], choiceBits)

		if err := base.Send(conn, q0Cols[j], q1Cols[j]); err != nil {
			return nil, err
		}

		uRows[j] = ot.XorBytes(q0Cols[j], q1Cols[j])
	}

	for j := 0; j < Kappa; j++ {
		if err := ot.WriteBytes(conn, uRows[j]); err != nil {
			return nil, err
		}
	}

	// 转成行矩阵，后面按 OT 编号 i 取对应的那一行
	q0Rows := transposeBits(q0Cols, n)
	q1Rows := transposeBits(q1Cols, n)

	result := make([][]byte, n)
	for i := 0; i < n; i++ {
		cipher0, err := ot.ReadBytes(conn)
		if err != nil {
			return nil, err
		}
		cipher1, err := ot.ReadBytes(conn)
		if err != nil {
			return nil, err
		}

		selectedRow := q0Rows[i]
		selectedCipher := cipher0
		if choices[i] == 1 {
			selectedRow = q1Rows[i]
			selectedCipher = cipher1
		}

		key := keyFromColumn(selectedRow)
		result[i] = ot.XorBytes(selectedCipher, key)
	}

	return result, nil
}
