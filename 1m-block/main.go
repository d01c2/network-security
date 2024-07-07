package main

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/AkihiroSuda/go-netfilter-queue"
	"github.com/google/gopacket/layers"
)

type TrieNode struct {
	children   map[rune]*TrieNode
	isTerminal bool
}
type Trie struct{ root *TrieNode }

func NewTrie() *Trie { return &Trie{root: &TrieNode{children: make(map[rune]*TrieNode)}} }
func (t *Trie) Insert(word string) {
	node := t.root
	for _, c := range word {
		if node.children[c] == nil {
			node.children[c] = &TrieNode{children: make(map[rune]*TrieNode)}
		}
		node = node.children[c]
	}
	node.isTerminal = true
}
func (t *Trie) Search(word string) bool {
	node := t.root
	for _, c := range word {
		if node.children[c] == nil {
			return false
		}
		node = node.children[c]
	}
	return node.isTerminal
}

var trie *Trie

func isFiltered(payload []byte) bool {
	t1 := time.Now()
	var host string
	reader := bufio.NewReader(strings.NewReader(string(payload)))
	for {
		if line, err := reader.ReadString('\n'); err != nil {
			break
		} else {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "Host:") {
				parts := strings.Split(line, " ")
				host = parts[1]
				break
			}
		}
	}
	ret := trie.Search(host)
	t2 := time.Now()
	if ret {
		timeDiff := t2.Sub(t1)
		fmt.Printf("[+] Time diff: %s\n", timeDiff)
	}
	return ret
}

func parseCsv(target string) (ret []string) {
	file, _ := os.Open(target)
	rdr := csv.NewReader(bufio.NewReader(file))
	rows, _ := rdr.ReadAll()
	for _, row := range rows {
		ret = append(ret, row[1])
	}
	return ret
}

func main() {
	if len(os.Args) < 2 {
		fmt.Printf("syntax : 1m-block <site list file>\n")
		fmt.Printf("sample : 1m-block top-1m.csv\n")
		panic("Invalid usage")
	}

	var urlListFile string = os.Args[1]
	harmfulUrls := parseCsv(urlListFile)
	trie = NewTrie()
	for _, url := range harmfulUrls {
		trie.Insert(url)
	}

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
			// fmt.Printf("packet received\n") // !debug
			// fmt.Println(p.Packet.Dump())    // !debug

			if tcpLayer := p.Packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
				tcp, _ := tcpLayer.(*layers.TCP)
				if tcp.SrcPort != 80 && tcp.DstPort != 80 {
					p.SetVerdict(netfilter.NF_ACCEPT)
				} else {
					payload := tcp.Payload
					if len(payload) == 0 {
						p.SetVerdict(netfilter.NF_ACCEPT)
					} else {
						if isFiltered(payload) {
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
