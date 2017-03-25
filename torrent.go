package main

import (
	//"bufio"
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	//"github.com/nictuku/dht"
	"github.com/zeebo/bencode"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	_ "reflect"
	"regexp"
	"strconv"
	"strings"
)

type TorrentData struct {
	info_hash     string
	left          int64
	downloaded    int64
	uploaded      int64
	announce_url  string
	announce_list []string
	//Use some sort of generator which follows convention for this. Currently S9NQEHHO48UDX16KDJWE is used always.
	peer_id      string
	pieces       [][]byte
	piece_length int64
	files        []File
	bitfield     []byte
	total_length int64
}

type File struct {
	length int64
	path   string
}

func (td TorrentData) getTrackerDataFromAnnounceList(tracker_data chan map[string]interface{}) {
	for i := range td.announce_list {
		go td.getTrackerData(td.announce_list[i], tracker_data)
	}
}

func (td TorrentData) getTrackerData(announce_url string, tracker_data chan map[string]interface{}) {
	encoded_hash := encodeInfoHash(hex.EncodeToString([]byte(td.info_hash)))
	announce_url += "?info_hash=" + encoded_hash + "&left=" + strconv.Itoa(int(td.left)) + "&compact=1"
	fmt.Println("QUERY URL IS ", announce_url)
	url, err := url.Parse(announce_url)
	handleErr(err)
	switch url.Scheme {
	case "http":
		response_string := td.getHTTPTrackerData(announce_url)
		response_map := bencodeStringToMap(response_string)
		response_map["peers"] = []byte(response_map["peers"].(string))
		tracker_data <- response_map
	case "udp":
		tracker_response := td.getUDPTrackerData(url)
		tracker_data <- tracker_response
	}
}

func (td TorrentData) getUDPTrackerData(url *url.URL) map[string]interface{} {
	udpAddr, err := net.ResolveUDPAddr("udp", url.Host)
	panicErr(err)
	conn, err := net.DialUDP("udp", nil, udpAddr)
	panicErr(err)
	var id uint64
	id, err = td.getUDPConnectionId(conn)
	panicErr(err)
	return td.getDataFromUDPConnection(conn, id)
}

//Refer to https://wiki.theory.org/BitTorrentSpecification#Metainfo_File_Structure
func getDataFromFile(file_name string) TorrentData {
	file_reader, err := os.Open(file_name)
	handleErr(err)
	decoder := bencode.NewDecoder(file_reader)
	var torrent interface{}
	err = decoder.Decode(&torrent)
	handleErr(err)
	torrent_map := torrent.(map[string]interface{})
	info := torrent_map["info"]
	announce_list_interface := torrent_map["announce-list"].([]interface{})
	var temp_interface []interface{}
	var announce_list []string
	for i := range announce_list_interface {
		temp_interface = announce_list_interface[i].([]interface{})
		announce_list = append(announce_list, temp_interface[0].(string))
	}
	announce_url := announce_list[0]
	if announce_url, exists := torrent_map["announce"]; !exists {
		fmt.Println("announce url not found")
	} else {
		fmt.Println("announce url found", announce_url)
	}
	handleErr(err)
	info_map := info.(map[string]interface{})
	var pieces [][]byte
	var piece_length int64
	var files []File
	for k, v := range info_map {
		if k == "files" {
			files = getFilesData(v)
		} else if k == "pieces" {
			pieces = getPiecesSlice([]byte(v.(string)))
		} else if k == "piece length" {
			piece_length = v.(int64)
		}
	}
	if len(files) == 0 && len(info_map["name"].(string)) > 0 {
		file_data_map := make(map[string]interface{})
		file_data_map["length"] = info_map["length"]
		file_data_map["path"] = []interface{}{info_map["name"]}
		files = getFilesData([]interface{}{file_data_map})
	}
	total_length := getTotalFileLength(files)
	bencoded_info, _ := bencode.EncodeString(info)
	h := sha1.New()
	h.Write([]byte(bencoded_info))
	sha1_hash := string(h.Sum(nil))
	//decoded, err := dht.DecodeInfoHash(sha1_hash)
	panicErr(err)
	bitfield := getBitfieldFromPieceCount(len(pieces))
	//Use 0 as amount of file downloaded for now. Handle this later
	torrent_data := TorrentData{
		info_hash:     sha1_hash,
		left:          total_length,
		downloaded:    int64(0),
		uploaded:      int64(0),
		announce_url:  announce_url,
		announce_list: announce_list,
		peer_id:       "S9NQEHHO48UDX16KDJWE",
		pieces:        pieces,
		piece_length:  piece_length,
		files:         files,
		bitfield:      bitfield,
		total_length:  total_length,
	}
	fmt.Println("Pieces and length are ", len(pieces), len(pieces)*int(piece_length), total_length, bitfield)
	createFiles(torrent_data)
	return torrent_data
}

func createFiles(td TorrentData) {
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
}

func getBitfieldFromPieceCount(num_pieces int) []byte {
	bitfield := make([]byte, (num_pieces+(num_pieces%16))/8)
	i := 0
	j := 0
	for i = 0; i < num_pieces-8; i += 8 {
		bitfield[j] = 255
		j++
	}
	bitfield_last := ""
	remaining := num_pieces - i
	for k := 0; k < remaining; k++ {
		bitfield_last += "1"
	}
	for k := len(bitfield_last); k < 8; k++ {
		bitfield_last += "0"
	}
	bitfield_byte, _ := strconv.ParseInt(bitfield_last, 2, 64)
	bitfield[len(bitfield)-1] = uint8(bitfield_byte)
	return bitfield
}

func getFilesData(raw_file_data interface{}) []File {
	files_interface := raw_file_data.([]interface{})
	var files []File
	for i := range files_interface {
		file_map := files_interface[i].(map[string]interface{})
		file_length := file_map["length"].(int64)
		file_path := "."
		file_path_elements := file_map["path"].([]interface{})
		for j := range file_path_elements {
			file_path += "/" + file_path_elements[j].(string)
		}
		files = append(files, File{length: file_length, path: file_path})
	}
	return files
}

func getPiecesSlice(pieces_bytes []byte) [][]byte {
	var num_pieces = len(pieces_bytes) / 20
	pieces_slice := make([][]byte, num_pieces)
	for i := range pieces_slice {
		pieces_slice[i] = make([]byte, 20)
		pieces_slice[i] = pieces_bytes[i*20 : i*20+20]
	}
	return pieces_slice
}

func bencodeStringToMap(bencode_string string) map[string]interface{} {
	var torrent interface{}
	_ = bencode.DecodeString(bencode_string, &torrent)
	torrent_map := torrent.(map[string]interface{})
	return torrent_map
}

func getTotalFileLength(files []File) int64 {
	var total_length int64
	total_length = 0
	for i := range files {
		total_length += files[i].length
	}
	return total_length
}

func hex2int(hexStr string) int {
	result, err := strconv.ParseInt(hexStr, 16, 64)
	handleErr(err)
	return int(result)
}

func encodeInfoHash(unencoded_hash string) string {
	r, _ := regexp.Compile(".{2}")
	sub_strings := r.FindAllString(unencoded_hash, -1)
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
	defer response.Body.Close()
	response_bytes, err := ioutil.ReadAll(response.Body)
	handleErr(err)
	return string(response_bytes)
}

func (td TorrentData) getHTTPTrackerData(announce_url string) string {
	conn, err := http.Get(announce_url)
	handleErr(err)
	response_string := handleResponse(conn)
	return response_string
}

//Check http://www.bittorrent.org/beps/bep_0015.html (BEP15) for details
func (td TorrentData) getUDPConnectionId(con *net.UDPConn) (connection_id uint64, err error) {
	var udp_request_id uint64 = 0x41727101980 //magic constant
	transaction_id := rand.Uint32()
	udp_request := new(bytes.Buffer)
	err = binary.Write(udp_request, binary.BigEndian, udp_request_id)
	panicErr(err)
	//send action as 0 for a connection request
	err = binary.Write(udp_request, binary.BigEndian, uint32(0))
	panicErr(err)
	err = binary.Write(udp_request, binary.BigEndian, transaction_id)
	panicErr(err)
	_, err = con.Write(udp_request.Bytes())
	panicErr(err)
	response_bytes := make([]byte, 16)
	_, err = con.Read(response_bytes)
	panicErr(err)
	connection_response := bytes.NewBuffer(response_bytes)
	var response_action uint32
	err = binary.Read(connection_response, binary.BigEndian, &response_action)
	panicErr(err)
	var response_transaction_id uint32
	err = binary.Read(connection_response, binary.BigEndian, &response_transaction_id)
	panicErr(err)

	err = binary.Read(connection_response, binary.BigEndian, &connection_id)
	if err != nil {
		return
	}
	return connection_id, nil
}

func (td TorrentData) getDataFromUDPConnection(con *net.UDPConn, connection_id uint64) map[string]interface{} {
	transaction_id := rand.Uint32()
	announce_request := new(bytes.Buffer)
	err := binary.Write(announce_request, binary.BigEndian, connection_id)
	panicErr(err)
	//send action as 1 for an announce request
	err = binary.Write(announce_request, binary.BigEndian, uint32(1))
	panicErr(err)
	err = binary.Write(announce_request, binary.BigEndian, transaction_id)
	panicErr(err)
	//binary.Write requires fixed size value or a slice of fixed slice values
	err = binary.Write(announce_request, binary.BigEndian, []byte(td.info_hash))
	panicErr(err)
	err = binary.Write(announce_request, binary.BigEndian, []byte(td.peer_id))
	panicErr(err)
	err = binary.Write(announce_request, binary.BigEndian, td.downloaded)
	panicErr(err)
	err = binary.Write(announce_request, binary.BigEndian, td.left)
	panicErr(err)
	err = binary.Write(announce_request, binary.BigEndian, td.uploaded)
	panicErr(err)
	//use '0' for event, which means none. Check BEP15 for the various event types and implement them
	err = binary.Write(announce_request, binary.BigEndian, uint32(0))
	panicErr(err)
	//use default ip address, 0.
	err = binary.Write(announce_request, binary.BigEndian, uint32(0))
	panicErr(err)
	err = binary.Write(announce_request, binary.BigEndian, uint32(0))
	panicErr(err)
	//number of peers wanted
	var num_want uint32 = 30
	err = binary.Write(announce_request, binary.BigEndian, num_want)
	panicErr(err)
	//specify port number to use
	err = binary.Write(announce_request, binary.BigEndian, uint16(6881))
	panicErr(err)
	_, err = con.Write(announce_request.Bytes())
	panicErr(err)

	response_len := 20 + 6*num_want
	responseBytes := make([]byte, response_len)

	_, err = con.Read(responseBytes)
	response := bytes.NewBuffer(responseBytes)
	udp_tracker_data := make(map[string]interface{})
	var response_action uint32
	err = binary.Read(response, binary.BigEndian, &response_action)
	panicErr(err)
	udp_tracker_data["response_action"] = response_action
	var response_transaction_id uint32
	err = binary.Read(response, binary.BigEndian, &response_transaction_id)
	panicErr(err)
	udp_tracker_data["response_transaction_id"] = response_transaction_id
	var interval uint32
	err = binary.Read(response, binary.BigEndian, &interval)
	panicErr(err)
	udp_tracker_data["interval"] = interval
	var leechers uint32
	err = binary.Read(response, binary.BigEndian, &leechers)
	panicErr(err)
	udp_tracker_data["leechers"] = leechers
	var seeders uint32
	err = binary.Read(response, binary.BigEndian, &seeders)
	panicErr(err)
	udp_tracker_data["seeders"] = seeders
	peer_bytes := make([]byte, 6*num_want)
	err = binary.Read(response, binary.BigEndian, &peer_bytes)
	panicErr(err)
	udp_tracker_data["peers"] = peer_bytes
	return udp_tracker_data
}
