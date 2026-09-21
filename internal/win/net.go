//go:build windows

package win

import (
	"encoding/binary"
	"fmt"
	"net"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Conn is one IPv4 TCP connection with its owning process.
type Conn struct {
	PID        uint32
	State      uint32
	LocalIP    net.IP
	LocalPort  uint16
	RemoteIP   net.IP
	RemotePort uint16
}

var (
	iphlpapi          = windows.NewLazySystemDLL("iphlpapi.dll")
	getExtendedTcpTbl = iphlpapi.NewProc("GetExtendedTcpTable")
)

const (
	afInet            = 2
	tcpTableOwnerPID  = 5 // TCP_TABLE_OWNER_PID_ALL
	mibTCPRowOwnerPID = 24
)

// StateName returns the TCP state name shown by netstat.
func StateName(s uint32) string {
	names := map[uint32]string{
		1: "CLOSED", 2: "LISTENING", 3: "SYN_SENT", 4: "SYN_RECEIVED",
		5: "ESTABLISHED", 6: "FIN_WAIT_1", 7: "FIN_WAIT_2", 8: "CLOSE_WAIT",
		9: "CLOSING", 10: "LAST_ACK", 11: "TIME_WAIT", 12: "DELETE_TCB",
	}
	if n, ok := names[s]; ok {
		return n
	}
	return fmt.Sprintf("STATE_%d", s)
}

// TCPConns returns the system's IPv4 TCP table (the data behind `netstat -ano`).
func TCPConns() ([]Conn, error) {
	var size uint32
	getExtendedTcpTbl.Call(0, uintptr(unsafe.Pointer(&size)), 1, afInet, tcpTableOwnerPID, 0)
	if size == 0 {
		return nil, fmt.Errorf("GetExtendedTcpTable: cannot size table")
	}

	// The table can grow between the two calls, so retry a few times.
	for try := 0; try < 4; try++ {
		buf := make([]byte, size+4096)
		size = uint32(len(buf))
		r, _, _ := getExtendedTcpTbl.Call(uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&size)), 1, afInet, tcpTableOwnerPID, 0)
		if r == uintptr(windows.ERROR_INSUFFICIENT_BUFFER) {
			continue
		}
		if r != 0 {
			return nil, fmt.Errorf("GetExtendedTcpTable: error %d", r)
		}
		return parseTCPTable(buf[:size]), nil
	}
	return nil, fmt.Errorf("GetExtendedTcpTable: table kept changing")
}

// parseTCPTable decodes MIB_TCPTABLE_OWNER_PID: a DWORD count followed by
// 24-byte rows {state, localAddr, localPort, remoteAddr, remotePort, pid}.
func parseTCPTable(b []byte) []Conn {
	if len(b) < 4 {
		return nil
	}
	n := int(binary.LittleEndian.Uint32(b))
	var out []Conn
	for i := 0; i < n; i++ {
		off := 4 + i*mibTCPRowOwnerPID
		if off+mibTCPRowOwnerPID > len(b) {
			break
		}
		r := b[off : off+mibTCPRowOwnerPID]
		out = append(out, Conn{
			State:      binary.LittleEndian.Uint32(r[0:4]),
			LocalIP:    net.IPv4(r[4], r[5], r[6], r[7]),
			LocalPort:  binary.BigEndian.Uint16(r[8:10]), // stored in network order
			RemoteIP:   net.IPv4(r[12], r[13], r[14], r[15]),
			RemotePort: binary.BigEndian.Uint16(r[16:18]),
			PID:        binary.LittleEndian.Uint32(r[20:24]),
		})
	}
	return out
}
