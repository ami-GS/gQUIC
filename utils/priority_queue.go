package utils

type MaxHeapUint64 []uint64

func (h MaxHeapUint64) Len() int           { return len(h) }
func (h MaxHeapUint64) Less(i, j int) bool { return h[i] > h[j] }
func (h MaxHeapUint64) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }

func (h *MaxHeapUint64) Push(x interface{}) {
	// Push and Pop use pointer receivers because they modify the slice's length,
	// not just its contents.
	*h = append(*h, x.(uint64))
}

func (h *MaxHeapUint64) Pop() interface{} {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[0 : n-1]
	return x
}

func (h *MaxHeapUint64) Delete() {
	*h = MaxHeapUint64{}
}
