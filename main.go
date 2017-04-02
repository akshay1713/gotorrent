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
	var tracker_data chan map[string]interface{} = make(chan map[string]interface{})
	go torrent_data.getTrackerDataFromAnnounceList(tracker_data)
	peer_connections := make(VerifiedPeerConnections)
	for {
		select {
		case torrent_map := <-tracker_data:
			if len(torrent_map) == 0 {
				fmt.Println("Empty map")
				continue
			}
			peer_bytes := torrent_map["peers"].([]byte)
			peers := getPeersFromByteSlice(peer_bytes)
			//fmt.Println("PEERS FOUND ARE ", len(peers))
			go connectToAllPeers(peers, torrent_data, peer_connections)
		}
	}
}
