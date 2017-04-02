package main

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
	return []byte{0, 0, 0, 1, 2}
}

func getMessageType(message []byte) string {
	message_types := map[byte]string{
		0: "choke",
		1: "unchoke",
		2: "interested",
		3: "not interested",
		4: "have",
		5: "bitfield",
		6: "request",
		7: "piece",
		8: "cancel",
		9: "port",
	}
	message_id := message[0]
	msg_type := message_types[message_id]
	if msg_type == "" {
		return "unknown"
	}
	return msg_type
}

func getRequestMessage(piece_index uint32, begin uint32, length uint32) []byte {
	msg := make([]byte, 17)
	getBytesFromUint32(msg[0:4], 13)
	msg[4] = 6
	getBytesFromUint32(msg[5:9], piece_index)
	getBytesFromUint32(msg[9:13], begin)
	getBytesFromUint32(msg[13:17], length)
	return msg
}
