package main

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"syscall"

	"k8s.io/klog/v2"
)

func main() {
	tcp := &TCPIP{
		IPHeader: &IPHeader{
			Version:  4,
			IHL:      5,
			TOS:      0,
			Length:   0x0028,
			ID:       0,
			Flags:    0,
			Fragment: 0,
			TTL:      64,
			Protocol: 6,
			Checksum: 0,
			Src:      net.ParseIP("10.107.160.43"),
			Dst:      net.ParseIP("10.168.119.134"),
		},
		SrcPort:  54321,
		DstPort:  80,
		Seq:      rand.Uint32(),
		Ack:      0,
		DataOff:  5,
		Reserved: 0,
		Flags:    0x2,
		Window:   0x7110,
		Checksum: 0,
		Urgent:   0,
	}

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		klog.Fatal(err)
	}
	defer syscall.Close(fd)

	err = syscall.BindToDevice(fd, "")
	if err != nil {
		klog.Fatal(err)
	}

	var dst [4]byte
	copy(dst[:], tcp.IPHeader.Dst.To4())
	addr := syscall.SockaddrInet4{
		Port: int(tcp.DstPort),
		Addr: dst,
	}

	payload := tcp.Bytes()
	klog.InfoS("Send payload", "payload", payload, "len", len(payload))
	err = syscall.Sendto(fd, tcp.Bytes(), 0, &addr)
	if err != nil {
		klog.Fatal(err)
	}

	res := make([]byte, 1500)
	syscall.Recvfrom(fd, res, 0)
}

type TCPIP struct {
	*IPHeader
	// TCPHeader
	SrcPort  uint16
	DstPort  uint16
	Seq      uint32
	Ack      uint32
	DataOff  uint8
	Reserved uint8
	Flags    uint16
	Window   uint16
	Checksum uint16
	Urgent   uint16
	Data     []byte
}

func (p *TCPIP) Complete() {
	p.IPHeader.Complete()

	var sum uint32

	sum += uint32(p.IPHeader.Protocol)
	sum += uint32(p.IPHeader.Src.To4()[0])<<8 + uint32(p.IPHeader.Src.To4()[1]) + uint32(p.IPHeader.Src.To4()[2])<<8 + uint32(p.IPHeader.Src.To4()[3])
	sum += uint32(p.IPHeader.Dst.To4()[0])<<8 + uint32(p.IPHeader.Dst.To4()[1]) + uint32(p.IPHeader.Dst.To4()[2])<<8 + uint32(p.IPHeader.Dst.To4()[3])
	sum += uint32(len(p.Data))

	sum += uint32(p.SrcPort) + uint32(p.DstPort) + uint32(p.Seq) + uint32(p.Ack)
	sum += uint32(p.DataOff)<<12 + uint32(p.Reserved)<<9 + uint32(p.Flags) + uint32(p.Window)
	sum += uint32(p.Checksum) + uint32(p.Urgent)

	checksum := uint16(sum>>16) + uint16(sum)
	checksum = 0xffff - checksum

	p.Checksum = checksum
}

func (p *TCPIP) Bytes() []byte {
	b := make([]byte, 40+len(p.Data))
	copy(b[0:20], p.IPHeader.Bytes())
	binary.BigEndian.PutUint16(b[20:22], p.SrcPort)
	binary.BigEndian.PutUint16(b[22:24], p.DstPort)
	binary.BigEndian.PutUint32(b[24:28], p.Seq)
	binary.BigEndian.PutUint32(b[28:32], p.Ack)
	b[32] = byte(p.DataOff<<4) | byte(p.Reserved<<1) | byte(p.Flags>>8)
	b[33] = byte(p.Flags)
	binary.BigEndian.PutUint16(b[34:36], p.Window)
	binary.BigEndian.PutUint16(b[36:38], p.Checksum)
	binary.BigEndian.PutUint16(b[38:40], p.Urgent)
	return b
}

func (p *TCPIP) String() string {
	var s strings.Builder
	for i, b := range p.Bytes() {
		s.WriteString(fmt.Sprintf("%02x ", b))
		if i%4 == 3 {
			s.WriteString("\n")
		}
	}
	return s.String()
}

type IPHeader struct {
	Version  uint8
	IHL      uint8
	TOS      uint8
	Length   uint16
	ID       uint16
	Flags    uint8
	Fragment uint16
	TTL      uint8
	Protocol uint8
	Checksum uint16
	Src      net.IP
	Dst      net.IP
}

// Complete completes the IP header by calculating the checksum
func (h *IPHeader) Complete() {
	var sum uint32
	sum += uint32(h.Version)<<12 + uint32(h.IHL)<<8 + uint32(h.TOS) + uint32(h.Length)
	sum += uint32(h.ID) + uint32(h.Flags)<<5 + uint32(h.Fragment)
	sum += uint32(h.TTL)<<8 + uint32(h.Protocol) + uint32(h.Checksum)
	sum += uint32(h.Src.To4()[0])<<8 + uint32(h.Src.To4()[1]) + uint32(h.Src.To4()[2])<<8 + uint32(h.Src.To4()[3])
	sum += uint32(h.Dst.To4()[0])<<8 + uint32(h.Dst.To4()[1]) + uint32(h.Dst.To4()[2])<<8 + uint32(h.Dst.To4()[3])

	checksum := uint16(sum>>16) + uint16(sum)
	checksum = 0xffff - checksum

	h.Checksum = checksum
}

// Bytes returns the byte representation of the IP header
func (h *IPHeader) Bytes() []byte {
	b := make([]byte, 20)
	b[0] = (h.Version << 4) | h.IHL
	b[1] = h.TOS
	binary.BigEndian.PutUint16(b[2:4], h.Length)
	binary.BigEndian.PutUint16(b[4:6], h.ID)
	b[6] = byte(h.Flags<<5) | byte(h.Fragment>>8)
	b[7] = byte(h.Fragment)
	b[8] = h.TTL
	b[9] = h.Protocol
	binary.BigEndian.PutUint16(b[10:12], h.Checksum)
	copy(b[12:16], h.Src.To4())
	copy(b[16:20], h.Dst.To4())
	return b
}

func (h *IPHeader) String() string {
	var s strings.Builder
	for i, b := range h.Bytes() {
		s.WriteString(fmt.Sprintf("%02x ", b))
		if i%4 == 3 {
			s.WriteString("\n")
		}
	}
	return s.String()
}
