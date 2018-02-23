package utils

// BigEndian

func MyPutUint64(wire []byte, dat uint64, size int) int {
	for i := 0; i < size; i++ {
		wire[i] = byte(dat >> byte(8*(size-i-1)))
	}
	return size
}

func MyUint64(wire []byte, frameLen int) (buff uint64) {
	for i := 0; i < frameLen; i++ {
		buff |= uint64(wire[i]) << byte(8*(frameLen-i-1))
	}
	return buff
}
