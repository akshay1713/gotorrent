package main

import (
	"fmt"
	//"github.com/zeebo/bencode"
	//"net"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Please enter the name of the torrent file")
		return
	}
	torrent_data := getDataFromFile(os.Args[1])
	torrent_map := torrent_data.getTrackerDataFromAnnounceList()
	for k, _ := range torrent_map {
		fmt.Println("KEY:------ \n", k)
	}
	peer_bytes := torrent_map["peers"].([]byte)
	//A slice of bytes. Each peers is represented by 6 bytes.
	//The first 4 are its IPv4 address, the next 2 are the port number
	peers := getPeersFromByteSlice(peer_bytes)
	fmt.Println("PEERS FOUND ARE ", len(peers))
	peer_connections := make(VerifiedPeerConnections)
	connectToAllPeers(peers, torrent_data, peer_connections)
}
