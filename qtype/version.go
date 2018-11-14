package qtype

import "math"

type Version uint32

//TODO: fill appropriate versions
const (
	VersionPlaceholder     Version = math.MaxUint32
	VersionQuicTLS         Version = 0x00000001
	VersionUnsupportedTest Version = 0x12345678
	VersionZero            Version = 0 // for test use
)

var SupportedVersions = []Version{VersionQuicTLS, VersionPlaceholder}

func (v Version) String() string {
	return map[Version]string{
		VersionPlaceholder:     "Placeholder",
		VersionQuicTLS:         "QuicTLS",
		VersionUnsupportedTest: "UnsupportedTest",
		VersionZero:            "Zero",
	}[v]
}
