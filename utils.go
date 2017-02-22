package main

import (
 "fmt"
)
func handleErr(err error) {
	if err != nil {
		fmt.Println("Error: ", err)
	}
}
