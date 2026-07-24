package classifier

import "sync"

const maxPooledClassifierSignalCapacity = 1 << 20

var classifierSignalPool sync.Pool

func takeClassifierSignalBuffer(length int) []bool {
	if length <= 0 {
		return nil
	}
	if pooled := classifierSignalPool.Get(); pooled != nil {
		buffer := pooled.([]bool)
		if cap(buffer) >= length {
			buffer = buffer[:length]
			clear(buffer)
			return buffer
		}
	}
	return make([]bool, length)
}

func putClassifierSignalBuffer(buffer []bool) {
	if cap(buffer) == 0 || cap(buffer) > maxPooledClassifierSignalCapacity {
		return
	}
	buffer = buffer[:cap(buffer)]
	clear(buffer)
	classifierSignalPool.Put(buffer[:0])
}
