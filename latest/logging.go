// or log package?
package quiclatest

import (
	"os"
	"strconv"
)

var LogLevel int

func init() {
	out := os.Getenv("DEBUG")
	if level, err := strconv.Atoi(out); err == nil && 1 <= level && level <= 3 {
		LogLevel = level
	}
}
