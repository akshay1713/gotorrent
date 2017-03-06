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
	//"reflect"
	"regexp"
	"strconv"
	"strings"
)

type TorrentData struct {
	info_hash     string
	left          int64
	downloaded    int64
	uploaded      int64
	files         []interface{}
	announce_url  string
	announce_list []string
	//Use some sort of generator which follows convention for this. Currently S9NQEHHO48UDX16KDJWE is used always.
	peer_id string
}

func (td TorrentData) getTrackerDataFromAnnounceList() map[string]interface{} {
	var tracker_response map[string]interface{}
	for i := range td.announce_list {
		tracker_response = td.getTrackerData(td.announce_list[i])
		if tracker_response != nil {
			return tracker_response
		}
	}
	return nil
}

func (td TorrentData) getTrackerData(announce_url string) map[string]interface{} {
	encoded_hash := encodeInfoHash(hex.EncodeToString([]byte(td.info_hash)))
	announce_url += "?info_hash=" + encoded_hash + "&left=" + strconv.Itoa(int(td.left)) + "&compact=1"
	fmt.Println("QUERY URL IS ", announce_url)
	url, err := url.Parse(announce_url)
	handleErr(err)
	fmt.Println("SCHEME IS ", url.Scheme)
	switch url.Scheme {
	case "http":
		response_string := td.getHTTPTrackerData(announce_url)
		response_map := bencodeStringToMap(response_string)
		response_map["peers"] = []byte(response_map["peers"].(string))
		return response_map
	case "udp":
		return td.getUDPTrackerData(url)
	}
	return nil
}

func (td TorrentData) getUDPTrackerData(url *url.URL) map[string]interface{} {
	fmt.Println("CONNECTING TO UDP TRACKER", url.Host)
	udpAddr, err := net.ResolveUDPAddr("udp", url.Host)
	panicErr(err)
	conn, err := net.DialUDP("udp", nil, udpAddr)
	panicErr(err)
	fmt.Println("CONN OBJECT IS ", conn)
	var id uint64
	id, err = td.getUDPConnectionId(conn)
	panicErr(err)
	return td.getDataFromUDPConnection(conn, id)
}

func (td TorrentData) getHandshakeRequest() string {
	//name of protocol
	pstr := "Bittorrent protocol"
	//length of protocol name
	pstrlen := `\x13`
	//8 bytes reserved for special use
	reserved := `\x00\x00\x00\x00\x00\x00\x00\x00`
	handshake_str := pstrlen + pstr + reserved + td.info_hash + td.peer_id
	return handshake_str
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
	var files []interface{}
	for k, v := range info_map {
		if k == "files" {
			files = v.([]interface{})
		}
	}
	total_length := getTotalFileLength(files)
	bencoded_info, _ := bencode.EncodeString(info)
	h := sha1.New()
	h.Write([]byte(bencoded_info))
	sha1_hash := string(h.Sum(nil))
	fmt.Println("SHA1 HASH IS ", sha1_hash, " ", len(sha1_hash))
	//decoded, err := dht.DecodeInfoHash(sha1_hash)
	panicErr(err)
	//Use 0 as amount of file downloaded for now. Handle this later
	torrent_data := TorrentData{sha1_hash, total_length, int64(0), int64(0), files, announce_url, announce_list, "S9NQEHHO48UDX16KDJWE"}
	return torrent_data
}

func bencodeStringToMap(bencode_string string) map[string]interface{} {
	var torrent interface{}
	_ = bencode.DecodeString(bencode_string, &torrent)
	torrent_map := torrent.(map[string]interface{})
	return torrent_map
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
	fmt.Println("handling response")
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
	fmt.Println("SENDING TRANSACTION ID ", transaction_id)
	var parameters []interface{}
	parameters = append(parameters, udp_request_id)
	parameters = append(parameters, uint32(0))
	parameters = append(parameters, transaction_id)
	udp_request := writeParamsToBuffer(parameters)
	_, err = con.Write(udp_request.Bytes())
	panicErr(err)
	response_bytes := make([]byte, 16)
	_, err = con.Read(response_bytes)
	fmt.Println(response_bytes)
	panicErr(err)
	connection_response := bytes.NewBuffer(response_bytes)
	var response_action uint32
	err = binary.Read(connection_response, binary.BigEndian, &response_action)
	fmt.Println("ACTION IS ", response_action)
	panicErr(err)
	var response_transaction_id uint32
	err = binary.Read(connection_response, binary.BigEndian, &response_transaction_id)
	fmt.Println("TRANSACTION ID FROM RESPONSE IS", response_transaction_id)
	panicErr(err)

	err = binary.Read(connection_response, binary.BigEndian, &connection_id)
	if err != nil {
		return
	}
	return connection_id, nil
}

func writeParamsToBuffer(parameters []interface{}) *bytes.Buffer {
	buf := new(bytes.Buffer)
	for i := range parameters {
		err := binary.Write(buf, binary.BigEndian, parameters[i])
		panicErr(err)
	}
	return buf
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
