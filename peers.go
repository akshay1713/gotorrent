package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	_ "reflect"
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

func (peer Peer) connectToPeer(connected_chan chan ConnectedPeer, td TorrentData) {
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
			peer_connections[ip_addr] = verified_peer.conn
			verified_peer.idle_peer_chan = idle_peer_chan
			verified_peer.remove_peer_chan = remove_peer_chan
			go verified_peer.saveBitfield()

			//case verified_peer := <-idle_peer_chan:
			//fmt.Println("bitfield of peer saved", verified_peer.ip.String()+":"+strconv.Itoa(int(verified_peer.port)))
			//idle_peers = append(idle_peers, verified_peer)
			//fmt.Println("Saved Idle peer")
		}
	}
}

func requestPieces(idle_peer_chan chan *VerifiedPeer, remove_peer_chan chan *VerifiedPeer, td TorrentData) {
	//var file_data_chan chan PieceBytes = make(chan PieceBytes)
	var piece_bitmask = td.bitfield
	var files = td.files
	file_descriptors := make([]*os.File, len(files))
	fmt.Println("Creating files", files)
	for i := range files {
		file_path := files[i].path
		dir := filepath.Dir(file_path)
		err := os.MkdirAll("./"+dir, 0777)
		panicErr(err)
		file_descriptors[i], err = os.Create(file_path)
		panicErr(err)
		fmt.Println("Created ", file_path)
	}
	for {
		select {
		case verified_peer := <-idle_peer_chan:
			peer_bitfield := verified_peer.bitfield
			piece_index := 0
			found := false
			for i := range piece_bitmask {
				if found {
					piece_index = i
					break
				}
				for j := range peer_bitfield {
					common := piece_bitmask[i] & peer_bitfield[j]
					if common == 0 {
						continue
					}
					common_bitmask := strconv.FormatInt(int64(common), 2)
					for k := 0; k < 8; k++ {
						if common_bitmask[k] == 1 {
							//This is the bit. Flip it.
							piece_bitmask[i] &^= (1 << uint(k))
						}
						piece_index = i*8 + k
						found = true
						break
					}
				}
			}
			if found {
				go verified_peer.getPiece(uint32(piece_index), td)
			} else {
				fmt.Println("No common bit found", verified_peer.bitfield)
			}
		}
	}
}

func (peer *VerifiedPeer) getPiece(piece_index uint32, td TorrentData) {
	fmt.Println("GETTING PIECE INDEX", piece_index)
	byte_count := piece_index*td.piece_length + td.piece_length
	if byte_count > td.total_length {
		fmt.Println("Last piece")
	}
	var block_size uint32 = 16384
	var block_pos uint32 = 0
	if block_size > td.piece_length {
		panic("Block size is greater than piece size")
	}
	fmt.Println("Piece length is ", td.piece_length)
	for block_pos < td.piece_length {
		peer.getBlock(piece_index, block_pos, block_size)
		block_pos += block_size
	}
	block_pos -= block_size
	remaining_length := td.piece_length - block_pos
	fmt.Println("remaining_length is ", remaining_length)
	if remaining_length > 0 {
		peer.getBlock(piece_index, block_pos, remaining_length)
	}
}
func (peer *VerifiedPeer) getBlock(piece_index uint32, begin uint32, length uint32) {
	req_msg := getRequestMessage(piece_index, begin, length)
	_, err := peer.conn.Write(req_msg)
	handleErr(err)
	file_bytes, err := peer.getNextMessage()
	fmt.Println("File bytes received", file_bytes, piece_index)
	handleErr(err)
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

func (peer *VerifiedPeer) saveBitfield() {
	fmt.Println("Verified peer connection is", peer.conn)
	bitfield, err := peer.getNextMessage()
	handleErr(err)
	msg_type, err := getMessageType(bitfield[0])
	if err != nil {
		fmt.Println("MESSAGE TYPE ERROR: ", err, bitfield[0])
		return
	}
	if msg_type != "bitfield" {
		fmt.Println("Msg type is not bitfield ", msg_type)
		return
	}
	fmt.Println("Bitfield is ", bitfield)
	peer.bitfield = bitfield[1:]
	peer.sendInterestedMessage()
	peer.getInitialhaveMessages()
	i_resp, err := peer.getNextMessage()
	handleErr(err)
	fmt.Println("RESPONSE TO INTEREST ", i_resp)
	peer.idle_peer_chan <- peer
}

func (peer *VerifiedPeer) sendInterestedMessage() {
	i_msg := getInterestedMessage()
	_, err := peer.conn.Write(i_msg)
	if err != nil {
		fmt.Println("Error while sending interested message", err)
	}
}

func (peer *VerifiedPeer) getInitialhaveMessages() {
	fmt.Println("Getting have messages")
	is_have := true
	for is_have {
		next_msg, err := peer.getNextMessage()
		if len(next_msg) == 0 {
			fmt.Println("Empty Message returned")
			return
		}
		if err != nil {
			fmt.Println("Error in getInitialhaveMessages", err, next_msg)
			continue
		}
		msg_type, err := getMessageType(next_msg[0])
		if err != nil {
			fmt.Println("Error in getInitialhaveMessages", err)
			continue
		}
		if msg_type != "have" {
			fmt.Println("Have message broken", msg_type)
			is_have = false
		}
		peer.sendInterestedMessage()
		fmt.Println("Have message received", next_msg)
	}
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
