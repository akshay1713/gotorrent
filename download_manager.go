package main

import (
	"fmt"
	"os"
)

func startDownloading(peer_connections VerifiedPeerConnections, tracker_data chan map[string]interface{}, torrent_data TorrentData) {
	var files = torrent_data.files
	var file_chan chan PieceBytes = make(chan PieceBytes)
	for {
		select {
		case torrent_map := <-tracker_data:
			if len(torrent_map) == 0 {
				fmt.Println("Empty map")
				continue
			}
			peer_bytes := torrent_map["peers"].([]byte)
			peers := getPeersFromByteSlice(peer_bytes)
			go connectToAllPeers(peers, torrent_data, peer_connections, file_chan)
		case piece_bytes := <-file_chan:
			current_piece_index := piece_bytes.piece_index
			current_piece := piece_bytes.data
			byte_position := current_piece_index * uint32(torrent_data.piece_length)
			for i := range files {
				if int64(byte_position) < files[i].length-int64(len(current_piece)) {
					file_ptr, err := os.OpenFile(files[i].path, os.O_WRONLY, 0777)
					handleErr(err)
					_, err = file_ptr.Seek(int64(byte_position), 0)
					_, err = file_ptr.Write(current_piece)
					handleErr(err)
					file_ptr.Close()
					break
				} else if int64(byte_position) < files[i].length {
					first_file_left := files[i].length - int64(byte_position)
					file_ptr, err := os.OpenFile(files[i].path, os.O_WRONLY, 0777)
					handleErr(err)
					_, err = file_ptr.Seek(int64(byte_position), 0)
					_, err = file_ptr.Write(current_piece[0:first_file_left])
					handleErr(err)
					file_ptr.Close()
					file_ptr, err = os.OpenFile(files[i+1].path, os.O_WRONLY, 0777)
					handleErr(err)
					_, err = file_ptr.Seek(0, 0)
					_, err = file_ptr.Write(current_piece[first_file_left:])
					handleErr(err)
					file_ptr.Close()
					break
				}
			}
		}
	}
}
