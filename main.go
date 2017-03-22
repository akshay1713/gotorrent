package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Please enter the name of the torrent file")
		return
	}
	torrent_data := getDataFromFile(os.Args[1])
	torrent_map := torrent_data.getTrackerDataFromAnnounceList()
	peer_bytes := torrent_map["peers"].([]byte)
	peers := getPeersFromByteSlice(peer_bytes)
	fmt.Println("PEERS FOUND ARE ", len(peers))
	peer_connections := make(VerifiedPeerConnections)
	connectToAllPeers(peers, torrent_data, peer_connections)
}
