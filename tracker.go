package main

import (
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
)

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

func handleResponse(response *http.Response) map[string]interface{} {
	defer response.Body.Close()
	_, _ = io.Copy(os.Stdout, response.Body)
	var test map[string]interface{}
	return test
}
