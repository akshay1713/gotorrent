package main

import (
	"fmt"
	//"github.com/zeebo/bencode"
	//"net"
	"os"
)

func main() {
	torrent_data := getDataFromFile(os.Args[1])
	torrent_map := torrent_data.getTrackerData()
	for k, _ := range torrent_map {
		fmt.Println("KEY:------ \n", k)
	}
	peer_bytes := torrent_map["peers"].([]byte)
	//A slice of bytes. Each peers is represented by 6 bytes.
	//The first 4 are its IPv4 address, the next 2 are the port number
	peers := getPeersFromByteSlice(peer_bytes)
	contacted := false
	peer_count := 0
	for !contacted {
		err := torrent_data.handshakeWithPeer(peers[peer_count])
		if peer_count == len(peers)-1 {
			break
		}
		if err != nil {
			fmt.Println("ERROR FROM CLIENT:\n", err)
			peer_count = peer_count + 1
			continue
		}
		contacted = true
	}
}
