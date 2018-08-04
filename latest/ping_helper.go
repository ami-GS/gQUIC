package quiclatest

import (
	"log"
	"sync"
	"time"

	"github.com/ami-GS/gQUIC/latest/qtype"
)

type PingHelper struct {
	Ticker       *time.Ticker
	infoMutex    *sync.Mutex
	timePingSent map[qtype.PacketNumber]time.Time
	pingDuration map[qtype.PacketNumber]time.Duration
}

func NewPingHelper(interval time.Duration) *PingHelper {
	return &PingHelper{
		Ticker:       time.NewTicker(interval),
		infoMutex:    new(sync.Mutex),
		timePingSent: make(map[qtype.PacketNumber]time.Time),
		pingDuration: make(map[qtype.PacketNumber]time.Duration),
	}
}

func (p *PingHelper) storeSendTime(pn qtype.PacketNumber) {
	p.infoMutex.Lock()
	defer p.infoMutex.Unlock()
	p.timePingSent[pn] = time.Now()
}

func (p *PingHelper) calcPingDuration(pn qtype.PacketNumber) {
	// TODO: not good for performance?
	if timeSent, ok := p.timePingSent[pn]; ok {
		p.infoMutex.Lock()
		p.pingDuration[pn] = time.Now().Sub(timeSent)
		delete(p.timePingSent, pn)
		p.infoMutex.Unlock()
		if LogLevel >= 0 {
			// TODO: needs more f
			log.Println(p.pingDuration)
		}
	}
}
