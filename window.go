package quic

type Window struct {
	initialSize int32
	currentSize int32
}

func NewWindow() (window *Window) {
	window = &Window{
		initialSize: 100, // TODO: set default size
		currentSize: 100,
	}
	return
}
