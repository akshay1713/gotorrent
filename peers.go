package main

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"
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

type VerifiedPeer struct {
	ip      net.IP
	port    uint16
	peer_id string
	conn    net.Conn
}

type VerifiedPeerConnections map[string]net.Conn

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

func (peer Peer) connectToPeer(connected_chan chan ConnectedPeer, td TorrentData, peer_connections VerifiedPeerConnections) {
	ip_addr := peer.ip.String() + ":" + strconv.Itoa(int(peer.port))
	conn, err := net.DialTimeout("tcp", ip_addr, 8*time.Second)
	if err != nil {
		fmt.Println("CONNECTION ERROR: ", err)
		return
	}
	connected_peer := ConnectedPeer{peer.ip, peer.port, conn}
	connected_chan <- connected_peer
}

func connectToAllPeers(peers []Peer, td TorrentData, peer_connections VerifiedPeerConnections) {
	var connected_chan chan ConnectedPeer = make(chan ConnectedPeer)
	var verified_chan chan VerifiedPeer = make(chan VerifiedPeer)
	for i := range peers {
		go peers[i].connectToPeer(connected_chan, td, peer_connections)
	}
	var pause string
	for {
		select {

		case connected_peer := <-connected_chan:
			fmt.Println("from peer connection gor", connected_peer)
			go connected_peer.handshake(td, verified_chan)

		case verified_peer := <-verified_chan:
			ip_addr := verified_peer.ip.String() + ":" + strconv.Itoa(int(verified_peer.port))
			peer_connections[ip_addr] = verified_peer.conn
			fmt.Println("Received verified peer ", verified_peer)
		}
	}
	fmt.Scanln(&pause)
}

func (peer ConnectedPeer) handshake(td TorrentData, verified_chan chan VerifiedPeer) {
	peer.sendHandshake(td)
	err := peer.completeHandshake()
	if err != nil {
		fmt.Println("Error while completing handshake", err)
		return
	}
	verified_peer := VerifiedPeer{peer.ip, peer.port, "ksajhf", peer.conn}
	verified_chan <- verified_peer
}

func (peer ConnectedPeer) sendHandshake(td TorrentData) {
	handshake_msg := getHandshakeMessage(td.info_hash, td.peer_id)
	fmt.Println(handshake_msg, len(handshake_msg))
	written, err := peer.conn.Write(handshake_msg)
	panicErr(err)
	fmt.Println(written, " bytes written during handshake")
}

func (peer ConnectedPeer) completeHandshake() error {
	response := make([]byte, 68)
	read, err := peer.conn.Read(response)
	if err != nil {
		return err
	}
	fmt.Println("response is ", response, " bytes read ", read)
	err = verifyHandshakeResponse(response)
	if err != nil {
		return err
	}
	fmt.Println("Response Handshake verified!")
	verified_peer_info := response[20:]
	fmt.Println("verified peer info ", verified_peer_info)
	return nil
}

func verifyHandshakeResponse(response []byte) error {
	protocol_name := "BitTorrent protocol"
	if response[0] != byte(len(protocol_name)) {
		return errors.New("Protocol name length not matched")
	}
	if string(response[1:20]) != protocol_name {
		return errors.New("Protocol name not matched " + string(response[1:20]))
	}
	return nil
}
