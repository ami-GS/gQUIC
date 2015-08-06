package quic

import (
	"encoding/binary"
	"fmt"
	//	"reflect"
)

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

func (tag QuicTag) String() string {
	m := map[QuicTag]string{
		CHLO: "CHLO",
		SHLO: "SHLO",
		REJ:  "REJ",
		SFCW: "SFCW",
		CFCW: "CFCW",
		VER:  "VER",
		SNI:  "SNI",
		STK:  "STK",
		PDMD: "PDMD",
		CCS:  "CCS",
		CCRT: "CCRT",
		SCFG: "SCFG",
		SNO:  "SNO",
		ff54: "ff54",
		PROF: "PROF",
		SCID: "SCID",
		KEXS: "KEXS",
		AEAD: "AEAD",
		PUBS: "PUBS",
		ORBT: "ORBT",
		EXPY: "EXPY",
		AESG: "AESG",
		S20P: "S20P",
		C255: "C255",
		P256: "P256",
		NONC: "NONC",
		CETV: "CETV",
		CIDK: "CIDK",
		CIDS: "CIDS",
		PRST: "PRST",
		RNON: "RNON",
		RSEQ: "RSEQ",
		CADR: "CADR",
	}
	return m[tag]
}

type Message struct {
	MsgTag QuicTag
	Tags   []QuicTag
	Values [][]byte
}

func NewMessage(msgTag QuicTag) *Message {
	switch msgTag {
	case CHLO, SHLO, REJ, PRST:
		message := &Message{
			MsgTag: msgTag,
			Tags:   []QuicTag{},
			Values: [][]byte{},
		}
		return message
	}
	return nil
}

func (message *Message) AppendTagValue(tag QuicTag, value []byte) bool {
	switch tag {
	case CHLO, SHLO, REJ, PRST:
		return false
	}
	if !message.TagContain(tag) {
		message.Tags = append(message.Tags, tag)
		message.Values = append(message.Values, value)
		return true
	}
	return false
}

func (message *Message) TagContain(tag QuicTag) bool {
	for _, t := range message.Tags {
		if t == tag {
			return true
		}
	}
	return false
}

func (message *Message) SortTags() {
	// TODO: consider that here should be quick sort
	tagNum := len(message.Tags)
	for i := 0; i < tagNum-1; i++ {
		for j := tagNum - 1; j > i; j-- {
			if message.Tags[j-1] < message.Tags[j] {
				tmpT := message.Tags[j]
				message.Tags[j] = message.Tags[j-1]
				message.Tags[j-1] = tmpT
				tmpV := message.Values[j]
				message.Values[j] = message.Values[j-1]
				message.Values[j-1] = tmpV
			}
		}
	}
}

func (message *Message) GetWire() (wire []byte, err error) {
	message.SortTags()

	valueLen := 0
	for _, v := range message.Values {
		valueLen += len(v)
	}
	tagNum := len(message.Tags)
	wire = make([]byte, 8+tagNum*8+valueLen)

	binary.BigEndian.PutUint32(wire, uint32(message.MsgTag))
	binary.BigEndian.PutUint16(wire[4:], uint16(tagNum))
	// padding 0x0000

	index := 8
	var endOffset uint32 = 0
	for i, tag := range message.Tags {
		endOffset += uint32(len(message.Values[i]))
		binary.BigEndian.PutUint32(wire[index:], uint32(tag))
		binary.BigEndian.PutUint32(wire[index+4:], endOffset)
		index += 8
	}
	for _, value := range message.Values {
		valLen := len(value)
		for j := 0; j < valLen; j++ {
			wire[index+j] = value[j]
		}
		index += valLen
	}
	return
}

func (message *Message) Parse(data []byte) (index int, err error) {
	message.MsgTag = QuicTag(binary.BigEndian.Uint32(data[0:4]))
	numPairs := binary.BigEndian.Uint16(data[4:6])
	message.Tags = make([]QuicTag, numPairs)
	message.Values = make([][]byte, numPairs)
	var valueFrom uint32 = 8 + uint32(numPairs)*8
	index = 8
	var prevOffset, endOffset uint32
	for i := 0; i < int(numPairs); i++ {
		message.Tags[i] = QuicTag(binary.BigEndian.Uint32(data[index : index+4]))
		endOffset = binary.BigEndian.Uint32(data[index+4:])
		message.Values[i] = make([]byte, endOffset-prevOffset)
		message.Values[i] = data[valueFrom : valueFrom+endOffset-prevOffset]
		valueFrom += endOffset
		prevOffset = endOffset
		index += 8
	}
	index += int(endOffset)

	message.SortTags()
	return
}

func (message *Message) String() string {
	str := fmt.Sprintf("Message tag:%s\n", message.MsgTag.String())
	for i, m := range message.Tags {
		str += fmt.Sprintf("\t%s:%v\n", m.String(), message.Values[i])
	}
	return str
}
