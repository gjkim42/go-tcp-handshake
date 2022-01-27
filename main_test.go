package main

import (
	"bytes"
	"fmt"
	"net"
	"testing"
)

func TestTCPIP(t *testing.T) {
	tcp := &TCPIP{
		IPHeader: &IPHeader{
			Version:  0x4,
			IHL:      0x5,
			TOS:      0x0,
			Length:   0x28,
			ID:       0xabcd,
			Flags:    0x0,
			Fragment: 0x0,
			TTL:      0x40,
			Protocol: 0x6,
			Checksum: 0x0,
			Src:      net.ParseIP("10.10.10.2"),
			Dst:      net.ParseIP("10.10.10.1"),
		},
		SrcPort:  12345,
		DstPort:  80,
		Seq:      0,
		Ack:      0,
		DataOff:  0x5,
		Reserved: 0x0,
		Flags:    0x2,
		Window:   0x7110,
		Checksum: 0x0,
		Urgent:   0x0,
		Data:     make([]byte, 20),
	}
	tcp.Complete()

	answer := []byte{
		0x45, 0x00, 0x00, 0x28,
		0xab, 0xcd, 0x00, 0x00,
		0x40, 0x06, 0xa6, 0xec,
		0x0a, 0x0a, 0x0a, 0x02,
		0x0a, 0x0a, 0x0a, 0x01,
		0x30, 0x39, 0x00, 0x50,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x50, 0x02, 0x71, 0x10,
		0xe6, 0x32, 0x00, 0x00,
	}

	if !bytes.Equal(tcp.Bytes(), answer) {
		t.Logf("got\n%s", tcp)
		t.Logf("want\n%s", hexdump(answer))
		t.Errorf("TCP packet is not correct")
	}
}

func hexdump(b []byte) string {
	var buf bytes.Buffer
	for i, b := range b {
		buf.WriteString(fmt.Sprintf("%02x ", b))
		if i%4 == 3 {
			buf.WriteString("\n")
		}
	}
	return buf.String()
}
