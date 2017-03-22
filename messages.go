package main

import (
	_ "encoding/binary"
	"errors"
)

//Refer to https://wiki.theory.org/BitTorrentSpecification#Handshake for details
func getHandshakeMessage(info_hash string, peer_id string) []byte {
	protocol_name := "BitTorrent protocol"
	handshake_msg := make([]byte, 68)
	//start with protocol name length
	handshake_msg[0] = byte(len(protocol_name))
	copy(handshake_msg[1:], []byte(protocol_name))
	//8 bytes are reserved
	copy(handshake_msg[20:27], []byte{0, 0, 0, 0, 0, 0, 0, 0})
	copy(handshake_msg[28:48], []byte(info_hash))
	copy(handshake_msg[48:68], []byte(peer_id))
	return handshake_msg
}

func getInterestedMessage() []byte {
	return []byte{1, 2}
}

func getMessageType(message_id byte) (string, error) {
	message_types := map[byte]string{
		4: "have",
		5: "bitfield",
		1: "interested",
	}
	msg_type := message_types[message_id]
	if msg_type == "" {
		return msg_type, errors.New("Message type not found")
	}
	return msg_type, nil
}

func getRequestMessage(piece_index uint32, begin uint32, length uint32) []byte {
	msg := make([]byte, 13)
	msg[0] = 6
	getBytesFromUint32(msg[1:5], piece_index)
	getBytesFromUint32(msg[5:9], begin)
	getBytesFromUint32(msg[9:13], length)
	return msg
}
