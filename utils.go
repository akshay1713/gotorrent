package main

import (
	"fmt"
)

func handleErr(err error) {
	if err != nil {
		fmt.Println("Error: ", err)
	}
}

func panicErr(err error) {
	if err != nil {
		panic(err)
	}
}

func getBytesFromUint32(source []byte, num uint32) {
	source[0] = byte(num >> 24)
	source[1] = byte(num >> 16)
	source[2] = byte(num >> 8)
	source[3] = byte(num)
}
