package main

import (
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

func getMessageType(message_id byte) (string, error) {
	message_types := map[byte]string{
		4: "have",
		5: "bitfield",
	}
	msg_type := message_types[message_id]
	if msg_type == "" {
		return msg_type, errors.New("Message type not found")
	}
	return msg_type, nil
}
