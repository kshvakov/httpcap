package main

import (
	"bytes"
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	"strings"
	"time"
)

var (
	device             = flag.String("device", "lo", "")
	BPFFilter          = flag.String("bpf_filter", "tcp and port 80", "")
	responseCodes      = flag.String("response_codes", "", "20x 30x 40x etc")
	slowRequestTime    = flag.Int64("slow_request_time", 0, "in milliseconds")
	requests           = make(map[string]request)
	printResponseCodes [][]byte
)

type request struct {
	method     string
	version    string
	requestURI string
	start      time.Time
}

func main() {

	flag.Parse()

	handle, err := pcap.OpenLive(*device, 1024, true, time.Second)

	defer handle.Close()

	if err != nil {

		log.Fatal(err)
	}

	codes := strings.Fields(*responseCodes)

	for _, code := range codes {

		c := []byte(code)

		if len(c) > 2 {

			printResponseCodes = append(printResponseCodes, c[:2])
		}
	}

	handle.SetBPFFilter(*BPFFilter)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	var (
		ipLayer  *layers.IPv4
		tcpLayer *layers.TCP
		ok       bool
	)

	for packet := range packetSource.Packets() {

		if applicationLayer := packet.ApplicationLayer(); applicationLayer != nil {

			if ipLayer, ok = packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4); !ok {

				continue
			}

			if tcpLayer, ok = packet.Layer(layers.LayerTypeTCP).(*layers.TCP); !ok {

				continue
			}

			playload := applicationLayer.Payload()

			if len(playload) < 5 {

				continue
			}

			i := bytes.Index(playload, []byte("\r\n"))

			if i == -1 {

				continue
			}

			chunks := bytes.Fields(playload[:i])

			if len(chunks) < 3 {

				continue
			}

			if bytes.Contains(playload[0:5], []byte("HTTP")) {

				from := fmt.Sprintf("%s%d:%s%d", ipLayer.DstIP, tcpLayer.DstPort, ipLayer.SrcIP, tcpLayer.SrcPort)

				if req, found := requests[from]; found {

					requestTime := packet.Metadata().Timestamp.Sub(req.start)

					if inCodes(chunks[1]) && (*slowRequestTime == 0 || requestTime.Nanoseconds() > *slowRequestTime*1000000) {

						fmt.Printf("-[ QUERY %f s]-:\nCode:%s\nMethod:%s\nRequestUri:%s\n\n\n", requestTime.Seconds(), string(chunks[1]), req.method, req.requestURI)
					}

					delete(requests, from)
				}

			} else {

				from := fmt.Sprintf("%s%d:%s%d", ipLayer.SrcIP, tcpLayer.SrcPort, ipLayer.DstIP, tcpLayer.DstPort)

				requests[from] = request{
					method:     string(chunks[0]),
					requestURI: string(chunks[1]),
					version:    string(chunks[2]),
					start:      packet.Metadata().Timestamp,
				}
			}
		}
	}
}

func inCodes(code []byte) bool {

	if len(printResponseCodes) == 0 || len(code) != 3 {

		return true
	}

	for _, c := range printResponseCodes {

		if c[0] == code[0] && c[1] == code[1] {

			return true
		}
	}

	return false
}
