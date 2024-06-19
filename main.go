package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const SNAPLEN = 1518

func checksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	sum = (sum >> 16) + (sum & 0xffff)
	sum += sum >> 16
	return uint16(^sum)
}

func tcpChecksum(ip *layers.IPv4, tcp *layers.TCP, payload []byte) uint16 {
	pseudoHeader := bytes.NewBuffer([]byte{})
	binary.Write(pseudoHeader, binary.BigEndian, ip.SrcIP.To4())
	binary.Write(pseudoHeader, binary.BigEndian, ip.DstIP.To4())
	pseudoHeader.WriteByte(0)
	pseudoHeader.WriteByte(byte(ip.Protocol))
	binary.Write(pseudoHeader, binary.BigEndian, uint16(len(tcp.Contents)+len(payload)))

	buf := bytes.NewBuffer(pseudoHeader.Bytes())
	binary.Write(buf, binary.BigEndian, tcp.Contents)
	binary.Write(buf, binary.BigEndian, payload)

	return checksum(buf.Bytes())
}

func sendRSTPacket(ip *layers.IPv4, tcp *layers.TCP) {
	conn, err := net.Dial("ip4:tcp", ip.DstIP.String())
	if err != nil {
		fmt.Printf("Dial error: %s\n", err)
		return
	}
	defer conn.Close()

	ipLayer := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    ip.DstIP,
		DstIP:    ip.SrcIP,
	}

	tcpLayer := &layers.TCP{
		SrcPort: tcp.DstPort,
		DstPort: tcp.SrcPort,
		Seq:     tcp.Ack,
		Window:  0,
		RST:     true,
	}

	tcpLayer.SetNetworkLayerForChecksum(ipLayer)
	tcpLayer.Checksum = tcpChecksum(ipLayer, tcpLayer, nil)
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	err = gopacket.SerializeLayers(buf, opts, ipLayer, tcpLayer)
	if err != nil {
		fmt.Printf("SerializeLayers error: %s\n", err)
		return
	}
	conn.Write(buf.Bytes())
}

func sendFINPacket(ip *layers.IPv4, tcp *layers.TCP) {
	conn, err := net.Dial("ip4:tcp", ip.DstIP.String())
	if err != nil {
		fmt.Printf("Dial error: %s\n", err)
		return
	}
	defer conn.Close()

	payload := "HTTP/1.0 302 Redirect\r\nLocation: http://warning.or.kr\r\n\r\n"
	ipLayer := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    ip.DstIP,
		DstIP:    ip.SrcIP,
	}

	tcpLayer := &layers.TCP{
		SrcPort: tcp.DstPort,
		DstPort: tcp.SrcPort,
		Seq:     tcp.Ack,
		Ack:     tcp.Seq + 1,
		FIN:     true,
		ACK:     true,
		Window:  0,
	}

	tcpLayer.SetNetworkLayerForChecksum(ipLayer)
	tcpLayer.Checksum = tcpChecksum(ipLayer, tcpLayer, []byte(payload))
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	if err = gopacket.SerializeLayers(buf, opts, ipLayer, tcpLayer, gopacket.Payload([]byte(payload))); err != nil {
		fmt.Printf("SerializeLayers error: %s\n", err)
	} else {
		conn.Write(buf.Bytes())
	}
}

func packetHandler(packet gopacket.Packet, pattern string) {
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	tcpLayer := packet.Layer(layers.LayerTypeTCP)

	if ipLayer == nil || tcpLayer == nil {
		return
	}

	ip, _ := ipLayer.(*layers.IPv4)
	tcp, _ := tcpLayer.(*layers.TCP)

	payload := string(tcp.Payload)
	if strings.Contains(payload, pattern) {
		fmt.Printf("Pattern found! Blocking...\n")
		sendRSTPacket(ip, tcp)
		time.Sleep(time.Second)
		sendFINPacket(ip, tcp)
		fmt.Printf("Blocked!!!\n")
	}
}

func main() {
	if len(os.Args) < 3 {
		fmt.Println("syntax : tcp-block <interface> <pattern>")
		fmt.Println("sample : tcp-block wlan0 \"Host: test.gilgil.net\"")
		panic("Invalid usage")
	}

	intf := os.Args[1]
	pattern := os.Args[2]

	if handle, err := pcap.OpenLive(intf, SNAPLEN, true, time.Second); err != nil {
		fmt.Printf("pcap_open_live(%s) return null\n", intf)
		panic(err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			packetHandler(packet, pattern)
		}
	}
}
