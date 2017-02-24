package main

import (
	"fmt"
	"github.com/zeebo/bencode"
	"net"
	"os"
)

type IP net.IP

func main() {
	//file_reader, err := os.Open(os.Args[1])
	torrent_data := getDataFromFile(os.Args[1])
	response_string := torrent_data.getTrackerData()
	fmt.Println(response_string)
	var torrent interface{}
	_ = bencode.DecodeString(response_string, &torrent)
	torrent_map := torrent.(map[string]interface{})
	for k, _ := range torrent_map {
		fmt.Println("KEY:------ \n", k)
	}
	peers_string := torrent_map["peers"].(string)
	peer_bytes := ([]byte(peers_string))
	fmt.Println(peer_bytes)
	fmt.Println(len(peer_bytes))
	var peers []Peer
	var ip net.IP
	var port uint16
	for i := 0; i < len(peer_bytes); i += 6 {
		fmt.Println(net.IPv4(peer_bytes[i], peer_bytes[i+1], peer_bytes[i+2], peer_bytes[i+3]))
		ip = net.IPv4(peer_bytes[i], peer_bytes[i+1], peer_bytes[i+2], peer_bytes[i+3])
		port = uint16(peer_bytes[i+4]) * 256
		fmt.Println(port)
		peers = append(peers, Peer{ip, port})
	}
}
