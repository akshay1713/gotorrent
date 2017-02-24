package main

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"github.com/zeebo/bencode"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
)

type TorrentData struct {
	info_hash    string
	left         int64
	files        []interface{}
	announce_url string
}

func (td TorrentData) getTrackerData() string {
	announce_url := td.announce_url
	announce_url += "?info_hash=" + td.info_hash + "&left=" + strconv.Itoa(int(td.left)) + "&compact=1"
	conn, err := http.Get(announce_url)
	handleErr(err)
	response_string := handleResponse(conn)
	return response_string
}

func getDataFromFile(file_name string) TorrentData {
	file_reader, err := os.Open(file_name)
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
	torrent_data := TorrentData{encoded_hash, total_length, files, announce_url}
	return torrent_data
}

func getTotalFileLength(files []interface{}) int64 {
	var total_length int64
	total_length = 0
	for i := range files {
		total_length += (files[i].(map[string]interface{})["length"]).(int64)
	}
	return total_length
}

func hex2int(hexStr string) int {
	result, err := strconv.ParseInt(hexStr, 16, 64)
	handleErr(err)
	return int(result)
}

func encodeInfoHash(info_hash string) string {
	r, _ := regexp.Compile(".{2}")
	sub_strings := r.FindAllString(info_hash, -1)
	encoded_info_hash := ""
	for _, single_unit := range sub_strings {
		char_code := hex2int(single_unit)
		uni_char := string(char_code)
		if char_code <= 127 {
			encoded := percentEncode(uni_char)
			if encoded[:1] == "%" {
				encoded = strings.ToLower(encoded)
			}
			encoded_info_hash += encoded
		} else {
			single_unit = "%" + single_unit
			encoded_info_hash += single_unit
		}
	}
	return encoded_info_hash
}

func percentEncode(str string) string {
	var regexEscapeURIComponent = regexp.MustCompile(`([^%])(\+)`)
	str = url.QueryEscape(str)
	return regexEscapeURIComponent.ReplaceAllString(str, "$1%20")
}

func handleResponse(response *http.Response) string {
	fmt.Println("handling response")
	defer response.Body.Close()
	response_bytes, err := ioutil.ReadAll(response.Body)
	handleErr(err)
	return string(response_bytes)
}
