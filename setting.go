package quic

type QuicTag uint32

const (
	CHLO QuicTag = 'C' + ('H' << 8) + ('L' << 16) + ('O' << 24)
	SHLO         = 'S' + ('H' << 8) + ('L' << 16) + ('O' << 24)
	REJ          = 'R' + ('E' << 8) + ('J' << 16) + (0 << 24)

	// in CHLO/SHLO
	// Stream Flow Control Window
	SFCW = 'S' + ('F' << 8) + ('C' << 16) + ('W' << 24)
	// Connection/Session Flow Control Window
	CFCW = 'C' + ('F' << 8) + ('C' << 16) + ('W' << 24)

	// in CHLO
	// Version
	VER = 'V' + ('E' << 8) + ('R' << 16) + (0 << 24)
	// Server Name Indication (optional)
	SNI = 'S' + ('N' << 8) + ('I' << 16) + (0 << 24)
	// Source-address token (optional)
	STK = 'S' + ('T' << 8) + ('K' << 16) + (0 << 24)
	// Proof demand (optional)
	PDMD = 'P' + ('D' << 8) + ('M' << 16) + ('D' << 24)
	// Common certificate sets (optional)
	CCS = 'C' + ('C' << 8) + ('S' << 16) + (0 << 24)
	// Cached certificate (optional)
	CCRT = 'C' + ('C' << 8) + ('R' << 16) + ('T' << 24)

	// in REJ
	// Server config (optional)
	SCFG = 'S' + ('C' << 8) + ('F' << 16) + ('G' << 24)
	// Server nonce (optional)
	SNO = 'S' + ('N' << 8) + ('O' << 16) + (0 << 24)
	// Certificate chain (optional)
	ff54 = 'f' + ('f' << 8) + ('5' << 16) + ('4' << 24)
	// Proof of authenticity (optional)
	PROF = 'P' + ('R' << 8) + ('O' << 16) + ('F' << 24)

	// in SCFG
	// Server config ID
	SCID = 'S' + ('C' << 8) + ('I' << 16) + ('D' << 24)
	// Key exchange algorithms
	KEXS = 'K' + ('E' << 8) + ('X' << 16) + ('S' << 24)
	// Authenticated encryption algorithms
	AEAD = 'A' + ('E' << 8) + ('A' << 16) + ('D' << 24)
	// A list of public values
	PUBS = 'P' + ('U' << 8) + ('B' << 16) + ('S' << 24)
	// Orbit
	ORBT = 'O' + ('R' << 8) + ('B' << 16) + ('T' << 24)
	// Expiry
	EXPY = 'E' + ('X' << 8) + ('P' << 16) + ('Y' << 24)
	// Version
	// VER = ... already defined

	// in AEAD
	// AES-GCM with a 12-byte tag and IV
	AESG = 'A' + ('E' << 8) + ('S' << 16) + ('G' << 24)
	// Salsa20 with Poly1305
	S20P = 'S' + ('2' << 8) + ('0' << 16) + ('P' << 24)
	// in KEXS
	// Curve25519
	C255 = 'C' + ('2' << 8) + ('5' << 16) + ('5' << 24)
	// P-256
	P256 = 'P' + ('2' << 8) + ('5' << 16) + ('6' << 24)

	// in full CHLO
	// SCID, AEAD, KEXS, SNO, PUBS
	// Client nonce
	NONC = 'N' + ('O' << 8) + ('N' << 16) + ('C' << 24)
	// Client encrypted tag-values (optional)
	CETV = 'C' + ('E' << 8) + ('T' << 16) + ('V' << 24)

	// in CETV
	// ChannelID key (optional)
	CIDK = 'C' + ('I' << 8) + ('D' << 16) + ('K' << 24)
	// ChnnelID signature (optional)
	CIDS = 'C' + ('I' << 8) + ('D' << 16) + ('S' << 24)

	// in Public Reset Packet
	PRST = 'P' + ('R' << 8) + ('S' << 16) + ('T' << 24)
	// public reset nonce proof
	RNON = 'R' + ('N' << 8) + ('O' << 16) + ('N' << 24)
	// rejected sequence number
	RSEQ = 'R' + ('S' << 8) + ('E' << 16) + ('Q' << 24)
	// client address
	CADR = 'C' + ('A' << 8) + ('D' << 16) + ('R' << 24)
	// got bored, write every names for future
)

const MTU = 1500 // TODO: need to check
