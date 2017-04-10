package main

import (
	_ "bufio"
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"reflect"
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
	remove_peer_chan chan *VerifiedPeer
	is_unchoked      bool
	is_active        bool
}

type PieceBytes struct {
	data        []byte
	piece_index uint32
}

type VerifiedPeerConnections map[string]bool
type BusyPeers []*VerifiedPeer
type IdlePeers []*VerifiedPeer

func getPeersFromByteSlice(peer_bytes []byte) []Peer {
	var peers []Peer
	var ip net.IP
	var port uint16
	for i := 0; i < len(peer_bytes); i += 6 {
		ip = net.IPv4(peer_bytes[i], peer_bytes[i+1], peer_bytes[i+2], peer_bytes[i+3])
		port = binary.BigEndian.Uint16([]byte{peer_bytes[i+4], peer_bytes[i+5]})
		peers = append(peers, Peer{ip, port})
	}
	return peers
}

func (peer Peer) connectToPeer(connected_chan chan ConnectedPeer, td TorrentData) {
	ip_addr := peer.ip.String() + ":" + strconv.Itoa(int(peer.port))
	conn, err := net.DialTimeout("tcp4", ip_addr, 10*time.Second)
	if err != nil {
		return
	}
	connected_peer := ConnectedPeer{peer.ip, peer.port, conn}
	connected_chan <- connected_peer
}

func connectToAllPeers(peers []Peer, td TorrentData, peer_connections VerifiedPeerConnections, file_chan chan PieceBytes) {
	var connected_chan chan ConnectedPeer = make(chan ConnectedPeer)
	var verified_chan chan VerifiedPeer = make(chan VerifiedPeer)
	var remove_peer_chan chan *VerifiedPeer = make(chan *VerifiedPeer)
	for i := range peers {
		if peers[i].ip.String() == "0.0.0.0" {
			continue
		}
		go peers[i].connectToPeer(connected_chan, td)
	}
	for {
		select {

		case connected_peer := <-connected_chan:
			go connected_peer.handshake(td, verified_chan)

		case verified_peer := <-verified_chan:
			ip_addr := verified_peer.ip.String()
			_, ok := peer_connections[ip_addr]
			if !ok {
				peer_connections[ip_addr] = true
				verified_peer.remove_peer_chan = remove_peer_chan
				go verified_peer.startMessageLoop(&td, file_chan)
			}

		case peer_to_remove := <-remove_peer_chan:
			err := peer_to_remove.conn.Close()
			handleErr(err)
			if err != nil {
				fmt.Println("Error while closing peer connection", err)
			}
			peer_connections[peer_to_remove.ip.String()] = false
		}
	}
}

func (peer *VerifiedPeer) startMessageLoop(td *TorrentData, file_chan chan PieceBytes) {
	//var files = td.files
	var current_length uint32
	var current_piece_index uint32
	var current_block_offset uint32
	last_piece := false
	current_piece := []byte{}
	var block_size uint32 = 16384
	var piece_length uint32 = uint32(td.piece_length)
	piece_complete := false
	peer.sendInterestedMessage()
	bitfield_length := len(td.bitfield)
	empty_bitfield := make([]byte, bitfield_length, bitfield_length)
	getting_piece := false
	for true {
		next_msg, err := peer.getNextMessage()
		if err != nil {
			fmt.Println("error in message loop", err, peer.ip, len(next_msg))
			getting_piece = false
			byte_to_reset := (current_piece_index - (current_piece_index % 8)) / 8
			bit_to_reset := 8 - (current_piece_index % 8)
			td.bitfield[byte_to_reset] |= 1 << bit_to_reset
		}
		if len(next_msg) > 0 {
			msg_type := getMessageType(next_msg)
			if getting_piece && msg_type != "piece" {
				byte_to_reset := (current_piece_index - (current_piece_index % 8)) / 8
				bit_to_reset := (current_piece_index % 8)
				td.bitfield[byte_to_reset] |= 1 << bit_to_reset
				next_piece_index := peer.requestPiece(td)
				if next_piece_index == -1 {
					fmt.Println("No common pieces found, returning")
					continue
				}
				current_piece_index = uint32(next_piece_index)
				current_block_offset = 0
				current_length, last_piece = peer.getBlockLength(current_piece_index, current_block_offset, block_size, td)
				peer.getBlock(current_piece_index, current_block_offset, current_length)
			}
			switch msg_type {
			case "bitfield":
				peer.bitfield = next_msg[1:]
				if reflect.DeepEqual(empty_bitfield, peer.bitfield) == true {
					return
				}
			case "have":
				fmt.Println("Have message", next_msg)
			case "unchoke":
				peer.is_unchoked = true
				if !piece_complete {
					getting_piece = true
					next_piece_index := peer.requestPiece(td)
					if next_piece_index == -1 {
						fmt.Println("No common pieces found, returning")
						continue
					}
					current_piece_index = uint32(next_piece_index)
					current_length, last_piece = peer.getBlockLength(current_piece_index, current_block_offset, block_size, td)
					peer.getBlock(current_piece_index, current_block_offset, current_length)
				} else {
					fmt.Println("Got unchoke while getting piece", current_piece_index, current_block_offset, peer.ip)
				}
			case "choke":
				peer.is_unchoked = false
			case "piece":
				recvd_piece_index := binary.BigEndian.Uint32(next_msg[1:5])
				recvd_block_offset := binary.BigEndian.Uint32(next_msg[5:9])
				recvd_block := next_msg[9:]
				if recvd_piece_index == current_piece_index && recvd_block_offset == current_block_offset {
					current_piece = append(current_piece, recvd_block...)
					current_block_offset += block_size
				}
				if current_block_offset >= piece_length || last_piece {
					hash := sha1.New()
					hash.Write(current_piece)
					piece_hash := hash.Sum(nil)
					if reflect.DeepEqual(piece_hash, td.pieces[current_piece_index]) || last_piece {
						last_piece = false
						fmt.Println("Piece complete", current_piece_index, td.pieces[current_piece_index], piece_hash)
						piece_bytes := PieceBytes{
							piece_index: current_piece_index,
							data:        current_piece,
						}
						getting_piece = false
						file_chan <- piece_bytes
						//byte_position := current_piece_index * uint32(td.piece_length)
					} else {
						fmt.Println("Piece not verified", current_piece_index)
					}
					piece_complete = true
					current_block_offset = 0
					current_piece = []byte{}
					getting_piece = true
					next_piece_index := peer.requestPiece(td)
					if next_piece_index == -1 {
						fmt.Println("No common pieces found, returning")
						continue
					}
					current_piece_index = uint32(next_piece_index)
					current_length, last_piece = peer.getBlockLength(current_piece_index, current_block_offset, block_size, td)
					peer.getBlock(current_piece_index, current_block_offset, current_length)
				} else {
					current_length, last_piece = peer.getBlockLength(current_piece_index, current_block_offset, block_size, td)
					peer.getBlock(current_piece_index, current_block_offset, current_length)
				}
			}
		} else {
			if getting_piece {
				byte_to_reset := (current_piece_index - (current_piece_index % 8)) / 8
				bit_to_reset := (current_piece_index % 8)
				td.bitfield[byte_to_reset] |= 1 << bit_to_reset
				next_piece_index := peer.requestPiece(td)
				if next_piece_index == -1 {
					fmt.Println("No common pieces found, returning")
					continue
				}
				current_piece_index = uint32(next_piece_index)
				current_block_offset = 0
				peer.getBlock(current_piece_index, current_block_offset, block_size)
			}
		}
	}
}

func (peer *VerifiedPeer) getBlockLength(current_piece_index uint32, current_block_offset uint32, block_size uint32, td *TorrentData) (uint32, bool) {
	num_pieces := uint32(len(td.pieces))
	piece_length := uint32(td.piece_length)
	if current_piece_index < num_pieces-1 {
		//Not the last piece
		return block_size, false
	} else {
		//Last piece
		total_length := uint32(td.total_length)
		//This is the length of the last piece
		length_diff := num_pieces*piece_length - total_length
		current_length := current_block_offset*block_size + block_size
		if current_length > length_diff {
			current_length = length_diff % block_size
		}
		return current_length, true
	}
}

func (peer *VerifiedPeer) updateBitfield(have []byte) {
}

func (peer *VerifiedPeer) requestPiece(td *TorrentData) int {
	peer_bitfield := peer.bitfield
	piece_bitmask := td.bitfield
	piece_index := -1
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
			common_bitmask := fmt.Sprintf("%08b", common)
			for k := 0; k < 8; k++ {
				if common_bitmask[k] == 49 {
					//This is the bit. Flip it.
					piece_bitmask[i] &^= (1 << byte(7-k))
					td.bitfield = piece_bitmask
					piece_index = i*8 + k
					found = true
					break
				}
			}
		}
	}
	return piece_index
}
func (peer *VerifiedPeer) getBlock(piece_index uint32, begin uint32, length uint32) {
	req_msg := getRequestMessage(piece_index, begin, length)
	_, err := peer.conn.Write(req_msg)
	if err != nil {
		fmt.Println("Error while getting block", err)
		peer.remove_peer_chan <- peer
	}
}

func (peer *VerifiedPeer) getNextMessage() ([]byte, error) {
	payload_length_msg := make([]byte, 4)
	_, err := io.ReadFull(peer.conn, payload_length_msg)
	if err != nil {
		if err == io.EOF {
			return []byte{}, nil
		}
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
	bitfield, err := peer.getNextMessage()
	handleErr(err)
	if len(bitfield) == 0 {
		fmt.Println("Empty bitfield returned", peer)
		return
	}
	msg_type := getMessageType(bitfield)
	if msg_type != "bitfield" {
		fmt.Println("Msg type is not bitfield ", msg_type)
		return
	}
	peer.bitfield = bitfield[1:]
	peer.getInitialhaveMessages()
}

func (peer *VerifiedPeer) sendInterestedMessage() {
	i_msg := getInterestedMessage()
	_, err := peer.conn.Write(i_msg)
	if err != nil {
		peer.is_active = false
		peer.remove_peer_chan <- peer
		return
	}
}

func (peer *VerifiedPeer) getInitialhaveMessages() {
	is_have := true
	for is_have {
		peer.sendInterestedMessage()
		next_msg, err := peer.getNextMessage()
		if len(next_msg) == 0 {
			return
		}
		if err != nil {
			peer.remove_peer_chan <- peer
			continue
		}
		msg_type := getMessageType(next_msg)
		if msg_type != "have" {
			is_have = false
			if msg_type == "unchoke" {
				peer.is_unchoked = true
			}
		}
	}
}

func (peer ConnectedPeer) handshake(td TorrentData, verified_chan chan VerifiedPeer) {
	peer.sendHandshake(td)
	response, err := peer.completeHandshake(td)
	if err != nil {
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
	_, err := peer.conn.Write(handshake_msg)
	if err != nil {
		fmt.Println("Error while sending handshake, closing connection", err)
		_ = peer.conn.Close()
	}
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
