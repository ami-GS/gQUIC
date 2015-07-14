package quic

type QuicTag uint32

const (
	CHLO QuicTag = 'C' + ('H' << 8) + ('L' << 16) + ('O' << 24)
	SHLO         = 'S' + ('H' << 8) + ('L' << 16) + ('O' << 24)
	REJ          = 'R' + ('E' << 8) + ('J' << 16) + (0 << 24)
	SFCW         = 'S' + ('F' << 8) + ('C' << 16) + ('W' << 24)
	CFCW         = 'C' + ('F' << 8) + ('C' << 16) + ('W' << 24)
	// got bored, write every names for future
)
