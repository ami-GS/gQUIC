package main

import (
	"fmt"
	"time"

	"github.com/ami-GS/gQUIC"
)

func runServer(addPair string) {
	s, err := quic.NewServer()
	if err != nil {
		fmt.Println(err)
	}
	err = s.ListenAndServe(addPair)
	fmt.Println(err)
}

func runClient(addPair string) {
	cli, _ := quic.NewClient(false)
	fmt.Println(cli.Connect(addPair))

	f := []quic.Frame{
		quic.NewStreamFrame(true, 1, 1, []byte("testData")),
	}
	cli.SendFramePacket(f)
}

func main() {
	addPair := "127.0.0.1:8080"
	go runServer(addPair)
	runClient(addPair)
	time.Sleep(1 * time.Second)
}
