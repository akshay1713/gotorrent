package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
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
	ip       net.IP
	port     uint16
	peer_id  string
	conn     net.Conn
	bitfield []byte
}

type VerifiedPeerConnections map[string]net.Conn

func getPeersFromByteSlice(peer_bytes []byte) []Peer {
	var peers []Peer
	var ip net.IP
	var port uint16
	for i := 0; i < len(peer_bytes); i += 6 {
		fmt.Println(peer_bytes[i], peer_bytes[i+1], peer_bytes[i+2], peer_bytes[i+3])
		ip = net.IPv4(peer_bytes[i], peer_bytes[i+1], peer_bytes[i+2], peer_bytes[i+3])
		port = binary.BigEndian.Uint16([]byte{peer_bytes[i+4], peer_bytes[i+5]})
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
		fmt.Println("Error while connecting to peer ", err)
		return
	}
	connected_peer := ConnectedPeer{peer.ip, peer.port, conn}
	connected_chan <- connected_peer
}

func connectToAllPeers(peers []Peer, td TorrentData, peer_connections VerifiedPeerConnections) {
	var connected_chan chan ConnectedPeer = make(chan ConnectedPeer)
	var verified_chan chan VerifiedPeer = make(chan VerifiedPeer)
	for i := range peers {
		if peers[i].ip.String() == "0.0.0.0" {
			continue
		}
		go peers[i].connectToPeer(connected_chan, td, peer_connections)
	}
	for {
		select {

		case connected_peer := <-connected_chan:
			go connected_peer.handshake(td, verified_chan)

		case verified_peer := <-verified_chan:
			ip_addr := verified_peer.ip.String() + ":" + strconv.Itoa(int(verified_peer.port))
			peer_connections[ip_addr] = verified_peer.conn
			go verified_peer.followUp()
		}
	}
}

func (peer *VerifiedPeer) getNextMessage() ([]byte, error) {
	payload_length_msg := make([]byte, 4)
	_, err := io.ReadFull(peer.conn, payload_length_msg)
	if err != nil {
		return []byte{}, errors.New("Error while getting message length")
	}
	payload_length := binary.BigEndian.Uint32(payload_length_msg)
	msg := make([]byte, payload_length)
	_, err = io.ReadFull(peer.conn, msg)
	if err != nil {
		return []byte{}, errors.New("Error while getting message")
	}
	return msg, nil
}

func (peer *VerifiedPeer) followUp() {
	fmt.Println("Verified peer connection is", peer.conn)
	bitfield, err := peer.getNextMessage()
	handleErr(err)
	msg_type, err := getMessageType(bitfield[0])
	if err != nil {
		fmt.Println("MESSAGE TYPE ERROR: ", err, bitfield[0])
		return
	}
	peer.bitfield = bitfield
	fmt.Println("Message from verified peer with type", bitfield, msg_type)
	i_msg := getInterestedMessage()
	_, err = peer.conn.Write(i_msg)
	if err != nil {
		fmt.Println("Error while sending interested message", err)
	}
	i_resp, err := peer.getNextMessage()
	handleErr(err)
	fmt.Println("RESPONSE TO INTEREST ", i_resp)
}

func (peer ConnectedPeer) handshake(td TorrentData, verified_chan chan VerifiedPeer) {
	peer.sendHandshake(td)
	response, err := peer.completeHandshake(td)
	if err != nil {
		fmt.Println("Error while completing handshake", err)
		return
	}
	verified_peer := VerifiedPeer{
		ip:      peer.ip,
		port:    peer.port,
		peer_id: string(response),
		conn:    peer.conn,
	}
	verified_chan <- verified_peer
}

func (peer ConnectedPeer) sendHandshake(td TorrentData) {
	handshake_msg := getHandshakeMessage(td.info_hash, td.peer_id)
	fmt.Println(handshake_msg, len(handshake_msg))
	_, err := peer.conn.Write(handshake_msg)
	panicErr(err)
}

func (peer ConnectedPeer) completeHandshake(td TorrentData) ([]byte, error) {
	response := make([]byte, 68)
	_, err := peer.conn.Read(response)
	if err != nil {
		return []byte{}, err
	}
	err = verifyHandshakeResponse(response, td)
	if err != nil {
		return []byte{}, err
	}
	fmt.Println("Response Handshake verified!")
	verified_peer_info := response[48:]
	return verified_peer_info, nil
}

func verifyHandshakeResponse(response []byte, td TorrentData) error {
	protocol_name := "BitTorrent protocol"
	if response[0] != byte(len(protocol_name)) {
		return errors.New("Protocol name length not matched")
	}
	if string(response[1:20]) != protocol_name {
		return errors.New("Protocol name not matched " + string(response[1:20]))
	}
	if !bytes.Equal(response[28:48], []byte(td.info_hash)) {
		return errors.New("Info hash not matched")
	}
	return nil
}
