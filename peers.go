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

type ConnectedPeer struct {
	ip   net.IP
	port uint16
	conn net.Conn
}

type PeerConnections map[string]net.Conn

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

func (peer Peer) connectToPeer(c chan ConnectedPeer, td TorrentData, peer_connections PeerConnections) {
	ip_addr := peer.ip.String() + ":" + strconv.Itoa(int(peer.port))
	conn, err := net.DialTimeout("tcp", ip_addr, 8000000000)
	if err != nil {
		fmt.Println("CONNECTION ERROR: ", err)
		return
	}
	fmt.Println("CONNECTION DETAILS ", ip_addr, conn, err)
	connected_peer := ConnectedPeer{peer.ip, peer.port, conn}
	c <- connected_peer
}

func connectToAllPeers(peers []Peer, td TorrentData, peer_connections PeerConnections) {
	var c chan ConnectedPeer = make(chan ConnectedPeer)
	for i := range peers {
		go peers[i].connectToPeer(c, td, peer_connections)
	}
	var pause string
	for {
		connected_peer := <-c
		fmt.Println("from peer connection gor", connected_peer)
		ip_addr := connected_peer.ip.String() + ":" + strconv.Itoa(int(connected_peer.port))
		peer_connections[ip_addr] = connected_peer.conn
		connected_peer.sendHandshake(td)
	}
	fmt.Scanln(&pause)
}

func (peer ConnectedPeer) sendHandshake(td TorrentData) {
	fmt.Println("Sending handshake")
	handshake_msg := getHandshakeMessage(td.info_hash, td.peer_id)
	fmt.Println(handshake_msg, len(handshake_msg))
}
