package qtype

// MTU for IPv4 packet
const MTUIPv4 = 1252

// MTU for IPv6 packet
const MTUIPv6 = 1232

// Long header's maximum size is 1+4+1+18+18+8+4=54
const MaxHeaderSize = 54

const MaxPayloadSizeIPv4 = MTUIPv4 - MaxHeaderSize
const MaxPayloadSizeIPv6 = MTUIPv6 - MaxHeaderSize

const HighPriorityWireSizeThreshold = MaxPayloadSizeIPv4 * 0.8
