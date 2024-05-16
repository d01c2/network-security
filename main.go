package main

import (
	"bytes"
	"fmt"
	"os"

	"github.com/AkihiroSuda/go-netfilter-queue"
	"github.com/google/gopacket/layers"
)

func isFiltered(payload []byte, host string) bool {
	return bytes.Contains(payload, []byte(host))
}

func main() {
	if len(os.Args) < 2 {
		fmt.Printf("syntax : netfilter-test <host>\n")
		fmt.Printf("sample : netfilter-test test.gilgil.net\n")
		panic("Invalid usage")
	}

	var host string = os.Args[1]

	nf, err := netfilter.NewNFQueue(0, 100, netfilter.NF_DEFAULT_PACKET_SIZE)
	if err != nil {
		fmt.Printf("error during nfq_open()\n")
		panic(err)
	}
	defer nf.Close()

	packets := nf.GetPackets()
	for {
		select {
		case p := <-packets:
			fmt.Printf("packet received\n") // !debug
			fmt.Println(p.Packet.Dump())    // !debug

			if tcpLayer := p.Packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
				tcp, _ := tcpLayer.(*layers.TCP)
				if tcp.SrcPort != 80 && tcp.DstPort != 80 {
					p.SetVerdict(netfilter.NF_ACCEPT)
				} else {
					payload := tcp.Payload
					if len(payload) == 0 {
						p.SetVerdict(netfilter.NF_ACCEPT)
					} else {
						if isFiltered(payload, host) {
							fmt.Printf("[+] Successfully filtered the host\n")
						} else {
							p.SetVerdict(netfilter.NF_ACCEPT)
						}
					}
				}
			} else {
				p.SetVerdict(netfilter.NF_ACCEPT)
			}
		}
	}
}
