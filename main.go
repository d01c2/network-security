package main

import (
	"fmt"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const BUFSIZ int32 = 512

var payload []byte

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
			// fmt.Printf("%d bytes captured\n", packet.Metadata().CaptureInfo.CaptureLength)
			if packet.Layer(layers.LayerTypeTCP) != nil {
				fmt.Printf("====================\n")

				/* Ethernet Header - src mac / dst mac */
				if ethLayer := packet.Layer(layers.LayerTypeEthernet); ethLayer != nil {
					fmt.Printf("[Ethernet Header Info]\n")
					eth, _ := ethLayer.(*layers.Ethernet)
					fmt.Printf("Src MAC: %02X:%02X:%02X:%02X:%02X:%02X\n", eth.SrcMAC[0], eth.SrcMAC[1], eth.SrcMAC[2], eth.SrcMAC[3], eth.SrcMAC[4], eth.SrcMAC[5])
					fmt.Printf("Dst MAC: %02X:%02X:%02X:%02X:%02X:%02X\n", eth.DstMAC[0], eth.DstMAC[1], eth.DstMAC[2], eth.DstMAC[3], eth.DstMAC[4], eth.DstMAC[5])
					fmt.Printf("\n")
				}

				/* IP Header - src ip / dst ip */
				if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
					fmt.Printf("[IP Header Info]\n")
					ip, _ := ipLayer.(*layers.IPv4)
					fmt.Printf("Src IP: %d.%d.%d.%d\n", ip.SrcIP[0], ip.SrcIP[1], ip.SrcIP[2], ip.SrcIP[3])
					fmt.Printf("Dst IP: %d.%d.%d.%d\n", ip.DstIP[0], ip.DstIP[1], ip.DstIP[2], ip.DstIP[3])
					fmt.Printf("\n")
				}

				/* TCP Header - src port / dst port */
				if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
					fmt.Printf("[TCP Header Info]\n")
					tcp, _ := tcpLayer.(*layers.TCP)
					fmt.Printf("Src Port: %d\n", tcp.SrcPort)
					fmt.Printf("Dst Port: %d\n", tcp.DstPort)
					payload = tcp.LayerPayload()
					fmt.Printf("\n")
				}

				/* Payload(Data) - hexadecimal value (MAX 20 bytes) */
				fmt.Printf("[Payload Info]\n")
				dataSize := len(payload)
				fmt.Printf("Payload Size: %d\n", dataSize)
				if dataSize > 0 {
					fmt.Printf("Payload Hex Value: ")
					for i := 0; i < 20 && i < dataSize; i++ {
						fmt.Printf("%02X ", payload[i])
					}
					fmt.Printf("\n")
				}

				fmt.Printf("====================\n")
			}
		}
	}
}
