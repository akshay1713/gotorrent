package main

import (
	"net"
)

type Peer struct {
	ip   net.IP
	port uint16
}
