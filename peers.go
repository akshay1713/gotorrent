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

func (peer Peer) connectToPeer(connected_chan chan ConnectedPeer, td TorrentData, peer_connections PeerConnections) {
	ip_addr := peer.ip.String() + ":" + strconv.Itoa(int(peer.port))
	conn, err := net.DialTimeout("tcp", ip_addr, 8000000000)
	if err != nil {
		fmt.Println("CONNECTION ERROR: ", err)
		return
	}
	fmt.Println("CONNECTION DETAILS ", ip_addr, conn, err)
	connected_peer := ConnectedPeer{peer.ip, peer.port, conn}
	connected_chan <- connected_peer
}

func connectToAllPeers(peers []Peer, td TorrentData, peer_connections PeerConnections) {
	var connected_chan chan ConnectedPeer = make(chan ConnectedPeer)
	for i := range peers {
		go peers[i].connectToPeer(connected_chan, td, peer_connections)
	}
	var pause string
	for {
		connected_peer := <-connected_chan
		fmt.Println("from peer connection gor", connected_peer)
		ip_addr := connected_peer.ip.String() + ":" + strconv.Itoa(int(connected_peer.port))
		peer_connections[ip_addr] = connected_peer.conn
		connected_peer.handshake(td)
	}
	fmt.Scanln(&pause)
}

func (peer ConnectedPeer) handshake(td TorrentData) {
	peer.sendHandshake(td)
	peer.completeHandshake()
}

func (peer ConnectedPeer) sendHandshake(td TorrentData) {
	fmt.Println("Sending handshake")
	handshake_msg := getHandshakeMessage(td.info_hash, td.peer_id)
	fmt.Println(handshake_msg, len(handshake_msg))
	written, err := peer.conn.Write(handshake_msg)
	panicErr(err)
	fmt.Println(written, " bytes written during handshake")
}

func (peer ConnectedPeer) completeHandshake() {
	response := make([]byte, 68)
	read, err := peer.conn.Read(response)
	if err != nil {
		fmt.Println("Error while reading from response", err)
	}
	fmt.Println("response is ", response, " bytes read ", read)
	expected_response := verifyHandshakeResponse(response)
	if !expected_response {
		fmt.Println("Response handshake not verified")
		return
	}
	fmt.Println("Response Handshake verified!")
	verified_peer_info := response[20:]
	fmt.Println("verified peer info ", verified_peer_info)
}

func verifyHandshakeResponse(response []byte) bool {
	protocol_name := "BitTorrent protocol"
	if response[0] != byte(len(protocol_name)) {
		fmt.Println("Protocol name length not matched")
		return false
	}
	if string(response[1:20]) != protocol_name {
		fmt.Println("Protocol name not matched ", string(response[1:20]))
		return false
	}
	return true
}
