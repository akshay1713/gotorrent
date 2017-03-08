package main

//Refer to https://wiki.theory.org/BitTorrentSpecification#Handshake for details
func getHandshakeMessage(info_hash string, peer_id string) []byte {
	protocol_name := "BitTorrent protocol"
	handshake_msg := make([]byte, 68)
	//start with protocol name length
	handshake_msg[0] = byte(len(protocol_name))
	copy(handshake_msg[1:], []byte(protocol_name))
	//8 bytes are reserved
	handshake_msg[25] = byte(0)
	copy(handshake_msg[28:48], []byte(info_hash))
	copy(handshake_msg[48:68], []byte(peer_id))
	return handshake_msg
}
