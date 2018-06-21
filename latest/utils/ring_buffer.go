package utils

// RingBuffer is just a ring buffer
type RingBuffer struct {
	buffer []interface{}
	head   int
	tail   int
	size   int
}

func NewRingBuffer(size int) *RingBuffer {
	return &RingBuffer{
		buffer: make([]interface{}, size),
		head:   0,
		tail:   0,
		size:   0,
	}
}

func (rb RingBuffer) Empty() bool {
	return rb.head == rb.tail
}
func (rb RingBuffer) Full() bool {
	return rb.head == (rb.tail+1)%len(rb.buffer)
}

func (rb *RingBuffer) Enqueue(item interface{}) {
	if rb.Full() {
		// TODO: error
	}
	rb.buffer[rb.tail] = item
	rb.tail = (rb.tail + 1) % len(rb.buffer)
	rb.size++
}

func (rb *RingBuffer) Dequeue() interface{} {
	if rb.Empty() {
		return nil
	}

	s := rb.buffer[rb.head]
	rb.head = (rb.head + 1) % len(rb.buffer)
	rb.size--
	return s
}
func (rb RingBuffer) Size() int {
	return rb.size
}
