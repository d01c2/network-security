package main

import (
	"fmt"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

const BUFSIZ int32 = 512

func main() {
	if len(os.Args) != 2 {
		fmt.Printf("syntax: pcap-test <interface>\n")
		fmt.Printf("sample: pcap-test wlan0\n")
		panic("Invalid usage")
	}

	var intf string = os.Args[1]

	if handle, err := pcap.OpenLive(intf, BUFSIZ, true, time.Second); err != nil {
		fmt.Printf("pcap_open_live(%s) return null\n", intf)
		panic(err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			fmt.Printf("%d bytes captured\n", packet.Metadata().CaptureInfo.CaptureLength)
		}
	}
}
