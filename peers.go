package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	//"reflect"
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
	ip               net.IP
	port             uint16
	peer_id          string
	conn             net.Conn
	bitfield         []byte
	idle_peer_chan   chan *VerifiedPeer
	remove_peer_chan chan *VerifiedPeer
	is_unchoked      bool
	is_active        bool
}

type PieceBytes struct {
	data        []byte
	piece_index int
}

type VerifiedPeerConnections map[string]net.Conn
type BusyPeers []*VerifiedPeer
type IdlePeers []*VerifiedPeer

func getPeersFromByteSlice(peer_bytes []byte) []Peer {
	var peers []Peer
	var ip net.IP
	var port uint16
	for i := 0; i < len(peer_bytes); i += 6 {
		//fmt.Println(peer_bytes[i], peer_bytes[i+1], peer_bytes[i+2], peer_bytes[i+3])
		ip = net.IPv4(peer_bytes[i], peer_bytes[i+1], peer_bytes[i+2], peer_bytes[i+3])
		port = binary.BigEndian.Uint16([]byte{peer_bytes[i+4], peer_bytes[i+5]})
		peers = append(peers, Peer{ip, port})
	}
	return peers
}

func (peer Peer) connectToPeer(connected_chan chan ConnectedPeer, td TorrentData) {
	ip_addr := peer.ip.String() + ":" + strconv.Itoa(int(peer.port))
	//raddr := net.TCPAddr{IP: peer.ip, Port: int(peer.port)}
	conn, err := net.DialTimeout("tcp4", ip_addr, 10*time.Second)
	if err != nil {
		//fmt.Println("Error while connecting to peer ", err)
		return
	}
	connected_peer := ConnectedPeer{peer.ip, peer.port, conn}
	connected_chan <- connected_peer
}

func connectToAllPeers(peers []Peer, td TorrentData, peer_connections VerifiedPeerConnections) {
	var connected_chan chan ConnectedPeer = make(chan ConnectedPeer)
	var verified_chan chan VerifiedPeer = make(chan VerifiedPeer)
	var idle_peer_chan chan *VerifiedPeer = make(chan *VerifiedPeer)
	var remove_peer_chan chan *VerifiedPeer = make(chan *VerifiedPeer)
	//var busy_peers BusyPeers
	//var idle_peers []*VerifiedPeer
	for i := range peers {
		if peers[i].ip.String() == "0.0.0.0" {
			continue
		}
		go peers[i].connectToPeer(connected_chan, td)
	}
	go requestPieces(idle_peer_chan, remove_peer_chan, td)
	for {
		select {

		case connected_peer := <-connected_chan:
			go connected_peer.handshake(td, verified_chan)

		case verified_peer := <-verified_chan:
			ip_addr := verified_peer.ip.String() + ":" + strconv.Itoa(int(verified_peer.port))
			connection, ok := peer_connections[ip_addr]
			if ok {
				fmt.Println("Existing Peer returned from multiple trackers", connection)
			} else {
				peer_connections[ip_addr] = verified_peer.conn
				verified_peer.idle_peer_chan = idle_peer_chan
				verified_peer.remove_peer_chan = remove_peer_chan
				go verified_peer.saveBitfield()
			}
		}
	}
}

func requestPieces(idle_peer_chan chan *VerifiedPeer, remove_peer_chan chan *VerifiedPeer, td TorrentData) {
	//var file_data_chan chan PieceBytes = make(chan PieceBytes)
	var piece_bitmask = td.bitfield
	for {
		select {
		case verified_peer := <-idle_peer_chan:
			fmt.Println("Received unchoked peer", verified_peer.bitfield)
			peer_bitfield := verified_peer.bitfield
			piece_index := 0
			found := false
			for i := range piece_bitmask {
				if found {
					break
				}
				for j := range peer_bitfield {
					if found {
						break
					}
					common := piece_bitmask[i] & peer_bitfield[j]
					if common == 0 {
						continue
					}
					fmt.Println("Comparing ", piece_bitmask[i], peer_bitfield[j], common, verified_peer.ip)
					common_bitmask := fmt.Sprintf("%08b", common)
					fmt.Println("common_bitmask is ", common_bitmask, peer_bitfield, td.bitfield)
					for k := 0; k < 8; k++ {
						if common_bitmask[k] == 49 {
							//This is the bit. Flip it.
							fmt.Println("Before flip", td.bitfield)
							piece_bitmask[i] &^= (1 << byte(7-k))
							td.bitfield = piece_bitmask
							fmt.Println("After flip", td.bitfield)
							piece_index = i*8 + k
							found = true
							break
						}
					}
				}
			}
			if found {
				go verified_peer.getPiece(uint32(piece_index), td)
			} else {
				fmt.Println("No common bit found", verified_peer.bitfield, piece_index)
			}
		}
	}
}

func (peer *VerifiedPeer) getPiece(piece_index uint32, td TorrentData) {
	fmt.Println("GETTING PIECE INDEX", piece_index)
	piece_length := uint32(td.piece_length)
	total_length := uint32(td.total_length)
	byte_count := piece_index*piece_length + piece_length
	if byte_count > total_length {
		fmt.Println("Last piece")
	}
	var block_size uint32 = 16384
	var block_pos uint32 = 0
	if block_size > piece_length {
		panic("Block size is greater than piece size")
	}
	fmt.Println("Piece length is ", piece_length)
	for block_pos < piece_length {
		peer.getBlock(piece_index, block_pos, block_size)
		block_pos += block_size
	}
	block_pos -= block_size
	remaining_length := piece_length - block_pos
	fmt.Println("remaining_length is ", remaining_length)
	if remaining_length > 0 {
		peer.getBlock(piece_index, block_pos, remaining_length)
	}
}

func (peer *VerifiedPeer) getBlock(piece_index uint32, begin uint32, length uint32) {
	fmt.Println("Getting block with data", begin, piece_index, peer.ip)
	req_msg := getRequestMessage(piece_index, begin, length)
	_, err := peer.conn.Write(req_msg)
	fmt.Println("Request message sent, waiting for response")
	if err != nil {
		fmt.Println("Error after getting unchoked", err)
		return
	}
	got_bytes := false
	for !got_bytes {
		file_bytes, err := peer.getNextMessage()
		if err != nil {
			fmt.Println("Error after getting unchoked", err)
			return
		}
		fmt.Println("File bytes received", file_bytes, piece_index, peer.ip, peer.bitfield)
		if len(file_bytes) == 0 {
			got_bytes = true
		}
	}
	handleErr(err)
}

func (peer *VerifiedPeer) getNextMessage() ([]byte, error) {
	payload_length_msg := make([]byte, 4)
	_, err := io.ReadFull(peer.conn, payload_length_msg)
	if err != nil {
		//if err == io.EOF {
		//return []byte{}, nil
		//}
		return []byte{}, err
	}
	payload_length := binary.BigEndian.Uint32(payload_length_msg)
	msg := make([]byte, payload_length)
	_, err = io.ReadFull(peer.conn, msg)
	if err != nil {
		return []byte{}, err
	}
	return msg, nil
}

func (peer *VerifiedPeer) saveBitfield() {
	//fmt.Println("Verified peer connection is", peer.conn)
	bitfield, err := peer.getNextMessage()
	handleErr(err)
	if len(bitfield) == 0 {
		fmt.Println("Empty bitfield returned", peer)
		return
	}
	msg_type, err := getMessageType(bitfield[0])
	if err != nil {
		//fmt.Println("MESSAGE TYPE ERROR: ", err, bitfield[0])
		return
	}
	if msg_type != "bitfield" {
		fmt.Println("Msg type is not bitfield ", msg_type)
		return
	}
	//fmt.Println("Bitfield is ", bitfield)
	peer.bitfield = bitfield[1:]
	peer.getInitialhaveMessages()
	if peer.is_unchoked {
		peer.idle_peer_chan <- peer
	} else {
		peer.UnchokePeer()
	}
}

func (peer *VerifiedPeer) sendInterestedMessage() {
	i_msg := getInterestedMessage()
	_, err := peer.conn.Write(i_msg)
	if err != nil {
		//fmt.Println("Error while sending interested message", err)
		peer.is_active = false
		return
	}
	msg_response, err := peer.getNextMessage()
	if err != nil {
		//fmt.Println("Error while getting response in sendInterestedMessage", err)
		peer.is_active = false
		return
	}
	if len(msg_response) == 0 {
		//fmt.Println("Empty message returned in sendInterestedMessage")
		return
	}
	msg_type, err := getMessageType(msg_response[0])
	if err != nil {
		//fmt.Println("Error while getting message type", err)
		return
	}
	if msg_type == "unchoke" {
		fmt.Println("Unchoke msg is ", msg_response)
		peer.is_unchoked = true
		fmt.Println("*********************\nIS UNCHOKED\n**********************", peer)
		peer.idle_peer_chan <- peer
	}
}

func (peer *VerifiedPeer) UnchokePeer() {
	for _ = range time.Tick(120 * time.Second) {
		if !peer.is_unchoked && peer.is_active {
			//fmt.Println("Sending interested message while unchoking")
			peer.sendInterestedMessage()
			if peer.is_unchoked {
				return
			}
			//fmt.Println("Still choked, scheduling unchoke attempt")
		} else {
			return
		}
	}
}
func (peer *VerifiedPeer) getInitialhaveMessages() {
	//fmt.Println("Getting have messages")
	is_have := true
	for is_have {
		peer.sendInterestedMessage()
		next_msg, err := peer.getNextMessage()
		if len(next_msg) == 0 {
			//fmt.Println("Empty Message returned while getting initial haves")
			return
		}
		if err != nil {
			//fmt.Println("Error in getInitialhaveMessages", err, next_msg)
			continue
		}
		msg_type, err := getMessageType(next_msg[0])
		if err != nil {
			//fmt.Println("Error in getInitialhaveMessages", err)
			continue
		}
		if msg_type != "have" {
			//fmt.Println("Have message broken", msg_type)
			is_have = false
			if msg_type == "unchoke" {
				peer.is_unchoked = true
			}
		}
		//fmt.Println("Have message received", next_msg)
	}
}

func (peer ConnectedPeer) handshake(td TorrentData, verified_chan chan VerifiedPeer) {
	peer.sendHandshake(td)
	response, err := peer.completeHandshake(td)
	if err != nil {
		//fmt.Println("Error while completing handshake", err)
		return
	}
	verified_peer := VerifiedPeer{
		ip:          peer.ip,
		port:        peer.port,
		peer_id:     string(response),
		conn:        peer.conn,
		is_unchoked: false,
		is_active:   true,
	}
	verified_chan <- verified_peer
}

func (peer ConnectedPeer) sendHandshake(td TorrentData) {
	handshake_msg := getHandshakeMessage(td.info_hash, td.peer_id)
	//fmt.Println(handshake_msg, len(handshake_msg))
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
	//fmt.Println("Response Handshake verified!")
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
