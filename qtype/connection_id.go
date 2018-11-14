package qtype

import (
	"bytes"
	"crypto/rand"
)

type ConnectionID []byte

const ConnectionIDLen = 18
const ConnectionIDLenMax = 18

func NewConnectionID(data []byte) (ConnectionID, error) {
	if data == nil {
		cid := make([]byte, ConnectionIDLen)
		_, err := rand.Read(cid)
		if err != nil {
			return nil, err
		}
		return ConnectionID(cid), nil
	} else if len(data) > ConnectionIDLenMax {
		// TODO: error
		return nil, nil
	}
	return ConnectionID(data), nil
}

func ReadConnectionID(data []byte, length int) (ConnectionID, error) {
	if len(data) < length {
		// TODO: error
		return nil, nil
	}
	return ConnectionID(data[:length]), nil
}

func (cleft ConnectionID) Equal(cright ConnectionID) bool {
	return bytes.Equal(cleft, cright)
}

func (c ConnectionID) Bytes() []byte {
	return []byte(c)
}

func (c ConnectionID) String() string {
	// used for session management (map[string]*Session) as well as Print
	return string(c.Bytes())
}
