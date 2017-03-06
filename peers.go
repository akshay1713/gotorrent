package main

import (
	"fmt"
	"net"
	"strconv"
)

type Peer struct {
	ip   net.IP
	port uint16
}

func getPeersFromByteSlice(peer_bytes []byte) []Peer {
	var peers []Peer
	var ip net.IP
	var port uint16
	for i := 0; i < len(peer_bytes); i += 6 {
		fmt.Println(peer_bytes[i], peer_bytes[i+1], peer_bytes[i+2], peer_bytes[i+3])
		ip = net.IPv4(peer_bytes[i], peer_bytes[i+1], peer_bytes[i+2], peer_bytes[i+3])
		//shift bits to handle endianness
		port = uint16(peer_bytes[i+4]) << 8
		port |= uint16(peer_bytes[i+5])
		peers = append(peers, Peer{ip, port})
	}
	return peers
}

func (peer Peer) handshakeWithPeer() error {
	return nil
}

func (peer Peer) connectToPeer() {
	fmt.Println("CONNECTING FROM GOR", peer.ip.String()+":"+strconv.Itoa(int(peer.port)))
	tcpAddr := net.TCPAddr{IP: peer.ip, Port: int(peer.port)}
	conn, err := net.DialTCP("tcp", nil, &tcpAddr)
	if err != nil {
		fmt.Println("CONNECTION ERROR: ", err)
		return
	}
	fmt.Println("CONNECTION DETAILS ", peer.ip.String(), conn, err)
}

func connectToAllPeers(peers []Peer) {
	fmt.Println("CONNECTING TO ALL PEERS ", len(peers))
	for i := range peers {
		go peers[i].connectToPeer()
	}
	var pause string
	fmt.Scanln(&pause)
}
