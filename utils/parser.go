package utils

import (
	"net"
	"strconv"
	"strings"
)

func ParseAddressPair(addPair string) (*net.UDPAddr, error) {
	splitdat := strings.Split(addPair, ":")
	var err error
	port := 80
	if len(splitdat) == 2 {
		port, err = strconv.Atoi(splitdat[1])
		if err != nil {
			return nil, err
		}
	} else if len(splitdat) > 2 {
		return nil, nil // TODO : invalid address
	}
	return &net.UDPAddr{
		IP:   net.ParseIP(splitdat[0]),
		Port: port,
	}, nil
}
