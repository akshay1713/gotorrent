package main

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"github.com/zeebo/bencode"
	"net/http"
	"os"
	"strconv"
)

func main() {
	file_reader, err := os.Open(os.Args[1])
	handleErr(err)
	decoder := bencode.NewDecoder(file_reader)
	var torrent interface{}
	err = decoder.Decode(&torrent)
	handleErr(err)
	torrent_map := torrent.(map[string]interface{})
	info := torrent_map["info"]
	announce_url := torrent_map["announce"].(string)
	handleErr(err)
	info_map := info.(map[string]interface{})
	var files []interface{}
	fmt.Println("The following information is available in the torrent file")
	for k, v := range info_map {
		fmt.Println(k)
		if k == "files" {
			files = v.([]interface{})
		}
	}
	total_length := getTotalFileLength(files)
	bencoded_info, _ := bencode.EncodeString(info)
	h := sha1.New()
	h.Write([]byte(bencoded_info))
	sha1_hash := hex.EncodeToString(h.Sum(nil))
	encoded_hash := encodeInfoHash(sha1_hash)
	announce_url += "?info_hash=" + encoded_hash + "&left=" + strconv.Itoa(int(total_length))
	conn, err := http.Get(announce_url)
	handleErr(err)
	handleResponse(conn)
}
