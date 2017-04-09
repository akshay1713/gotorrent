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
	startDownloading(peer_connections, tracker_data, torrent_data)
}
