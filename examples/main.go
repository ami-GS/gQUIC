package main

import (
	"time"

	quic "github.com/ami-GS/gQUIC"
)

func main() {
	_, err := quic.ListenAddr("127.0.0.1:8080")
	if err != nil {
		panic(err)
	}

	cli, err := quic.DialAddr("127.0.0.1:8080")
	if err != nil {
		panic(err)
	}

	dataSize := 2000
	basedata := make([]byte, dataSize)
	for i := 0; i < dataSize; i++ {
		basedata[i] = byte(i%126) + 49
	}
	time.Sleep(500 * time.Millisecond)
	for i := 0; i < 3; i++ {
		basedata = append(basedata, '@')
		go cli.Send(basedata)
	}

	time.Sleep(1 * time.Second)

	cli.Ping()
	time.Sleep(500 * time.Millisecond)

	cli.Close()
	time.Sleep(2 * time.Second)
}
