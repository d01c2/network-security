package main

import (
	"encoding/binary"
	"fmt"
	"os"
)

func readNBO(path string) uint32 {
	num, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	return binary.BigEndian.Uint32(num)
}

func main() {
	if len(os.Args) != 3 {
		fmt.Printf("syntax : add-nbo <file1> <file2>\n")
		fmt.Printf("sample : add-nbo a.bin c.bin\n")
		panic("Invalid usage")
	}

	fst, snd := readNBO(os.Args[1]), readNBO(os.Args[2])
	res := fst + snd

	fmt.Printf("%d(0x%x) + %d(0x%x) = %d(0x%x)\n", fst, fst, snd, snd, res, res)
}
