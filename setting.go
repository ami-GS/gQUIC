package quic

type QuicTag uint32

const (
	CHLO QuicTag = 'C' + ('H' << 8) + ('L' << 16) + ('O' << 24)
	SHLO QuicTag = 'S' + ('H' << 8) + ('L' << 16) + ('O' << 24)
	REJ  QuicTag = 'R' + ('E' << 8) + ('J' << 16) + (0 << 24)

	// in CHLO/SHLO
	// Stream Flow Control Window
	SFCW QuicTag = 'S' + ('F' << 8) + ('C' << 16) + ('W' << 24)
	// Connection/Session Flow Control Window
	CFCW QuicTag = 'C' + ('F' << 8) + ('C' << 16) + ('W' << 24)

	// in CHLO
	// Version
	VER QuicTag = 'V' + ('E' << 8) + ('R' << 16) + (0 << 24)
	// Server Name Indication (optional)
	SNI QuicTag = 'S' + ('N' << 8) + ('I' << 16) + (0 << 24)
	// Source-address token (optional)
	STK QuicTag = 'S' + ('T' << 8) + ('K' << 16) + (0 << 24)
	// Proof demand (optional)
	PDMD QuicTag = 'P' + ('D' << 8) + ('M' << 16) + ('D' << 24)
	// Common certificate sets (optional)
	CCS QuicTag = 'C' + ('C' << 8) + ('S' << 16) + (0 << 24)
	// Cached certificate (optional)
	CCRT QuicTag = 'C' + ('C' << 8) + ('R' << 16) + ('T' << 24)

	// in REJ
	// Server config (optional)
	SCFG QuicTag = 'S' + ('C' << 8) + ('F' << 16) + ('G' << 24)
	// Server nonce (optional)
	SNO QuicTag = 'S' + ('N' << 8) + ('O' << 16) + (0 << 24)
	// Certificate chain (optional)
	ff54 QuicTag = 'f' + ('f' << 8) + ('5' << 16) + ('4' << 24)
	// Proof of authenticity (optional)
	PROF QuicTag = 'P' + ('R' << 8) + ('O' << 16) + ('F' << 24)

	// in SCFG
	// Server config ID
	SCID QuicTag = 'S' + ('C' << 8) + ('I' << 16) + ('D' << 24)
	// Key exchange algorithms
	KEXS QuicTag = 'K' + ('E' << 8) + ('X' << 16) + ('S' << 24)
	// Authenticated encryption algorithms
	AEAD QuicTag = 'A' + ('E' << 8) + ('A' << 16) + ('D' << 24)
	// A list of public values
	PUBS QuicTag = 'P' + ('U' << 8) + ('B' << 16) + ('S' << 24)
	// Orbit
	ORBT QuicTag = 'O' + ('R' << 8) + ('B' << 16) + ('T' << 24)
	// Expiry
	EXPY QuicTag = 'E' + ('X' << 8) + ('P' << 16) + ('Y' << 24)
	// Version
	// VER QuicTag = ... already defined

	// in AEAD
	// AES-GCM with a 12-byte tag and IV
	AESG QuicTag = 'A' + ('E' << 8) + ('S' << 16) + ('G' << 24)
	// Salsa20 with Poly1305
	S20P QuicTag = 'S' + ('2' << 8) + ('0' << 16) + ('P' << 24)
	// in KEXS
	// Curve25519
	C255 QuicTag = 'C' + ('2' << 8) + ('5' << 16) + ('5' << 24)
	// P-256
	P256 QuicTag = 'P' + ('2' << 8) + ('5' << 16) + ('6' << 24)

	// in full CHLO
	// SCID, AEAD, KEXS, SNO, PUBS
	// Client nonce
	NONC QuicTag = 'N' + ('O' << 8) + ('N' << 16) + ('C' << 24)
	// Client encrypted tag-values (optional)
	CETV QuicTag = 'C' + ('E' << 8) + ('T' << 16) + ('V' << 24)

	// in CETV
	// ChannelID key (optional)
	CIDK QuicTag = 'C' + ('I' << 8) + ('D' << 16) + ('K' << 24)
	// ChnnelID signature (optional)
	CIDS QuicTag = 'C' + ('I' << 8) + ('D' << 16) + ('S' << 24)

	// in Public Reset Packet
	PRST QuicTag = 'P' + ('R' << 8) + ('S' << 16) + ('T' << 24)
	// public reset nonce proof
	RNON QuicTag = 'R' + ('N' << 8) + ('O' << 16) + ('N' << 24)
	// rejected sequence number
	RSEQ QuicTag = 'R' + ('S' << 8) + ('E' << 16) + ('Q' << 24)
	// client address
	CADR QuicTag = 'C' + ('A' << 8) + ('D' << 16) + ('R' << 24)
	// got bored, write every names for future
)

const MTU = 1500 // TODO: need to check
