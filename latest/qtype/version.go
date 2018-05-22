package qtype

import "math"

type Version uint32

//TODO: fill appropriate versions
const (
	VersionPlaceholder Version = math.MaxUint32
	VersionQuicTLS     Version = 0x00000001
	VersionZero        Version = 0 // for test use
)

var SupportedVersions = []Version{VersionZero}
