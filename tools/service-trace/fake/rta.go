package fake

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
)

// upgradeReply answers the exact WebSocket challenge without negotiating compression.
func upgradeReply(header http.Header) Reply {
	h := http.Header{}
	h.Set("Connection", "Upgrade")
	h.Set("Upgrade", "websocket")
	h.Set("Sec-WebSocket-Protocol", "rta.xboxlive.com.V2")
	sum := sha1.Sum([]byte(header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	h.Set("Sec-WebSocket-Accept", base64.StdEncoding.EncodeToString(sum[:]))
	return Reply{Status: 101, Header: h}
}

// rtaTransport provides a full-duplex upgrade inside the Go synctest clock.
func (s *Server) rtaTransport(req *http.Request, r Reply) *http.Response {
	client, peer := net.Pipe()
	go s.rta(peer)
	return &http.Response{StatusCode: 101, Status: "101 Switching Protocols", ProtoMajor: 1, ProtoMinor: 1,
		Header: r.Header, Body: client, ContentLength: -1, Request: req}
}

// rtaHTTP upgrades the Rust driver's real TLS socket and preserves buffered incoming bytes.
func (s *Server) rtaHTTP(w http.ResponseWriter, r Reply) {
	conn, rw, err := http.NewResponseController(w).Hijack()
	if err != nil {
		return
	}
	if _, err = fmt.Fprint(rw, "HTTP/1.1 101 Switching Protocols\r\n"); err != nil {
		conn.Close()
		return
	}
	if err = r.Header.Write(rw); err != nil {
		conn.Close()
		return
	}
	if _, err = fmt.Fprint(rw, "\r\n"); err != nil {
		conn.Close()
		return
	}
	if err = rw.Flush(); err != nil {
		conn.Close()
		return
	}
	s.rta(&bufferedConn{Conn: conn, reader: rw.Reader})
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

// Read retains any frame prefix already read alongside the HTTP upgrade.
func (c *bufferedConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

// DropRTA closes only this scenario's sockets to trigger client recovery.
func (s *Server) DropRTA() {
	s.mu.Lock()
	var conns []io.ReadWriteCloser
	for conn := range s.rtaConns {
		conns = append(conns, conn)
	}
	s.mu.Unlock()
	for _, conn := range conns {
		_ = conn.Close()
	}
}

// rta implements just the bounded RFC6455 text/control frames used by these scenarios.
func (s *Server) rta(conn io.ReadWriteCloser) {
	s.mu.Lock()
	if s.rtaConns == nil {
		s.rtaConns = map[io.ReadWriteCloser]bool{}
	}
	s.state.Issued["connection"]++
	connection := s.state.Issued["connection"]
	s.rtaConns[conn] = true
	s.mu.Unlock()
	defer func() { conn.Close(); s.mu.Lock(); delete(s.rtaConns, conn); s.mu.Unlock() }()
	nextSubscription := 0
	for {
		var h [2]byte
		if _, err := io.ReadFull(conn, h[:]); err != nil {
			return
		}
		length := uint64(h[1] & 127)
		if length == 126 {
			var n uint16
			if binary.Read(conn, binary.BigEndian, &n) != nil {
				return
			}
			length = uint64(n)
		}
		if length > 65535 || h[0]&128 == 0 || h[1]&128 == 0 {
			return
		}
		var mask [4]byte
		if _, err := io.ReadFull(conn, mask[:]); err != nil {
			return
		}
		payload := make([]byte, int(length))
		if _, err := io.ReadFull(conn, payload); err != nil {
			return
		}
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
		opcode := h[0] & 15
		if opcode == 8 {
			return
		}
		if opcode == 9 {
			if writeRTAFrame(conn, 10, payload) != nil {
				return
			}
			continue
		}
		if opcode != 1 {
			continue
		}
		var request []json.RawMessage
		if json.Unmarshal(payload, &request) != nil || len(request) != 3 {
			return
		}
		var op, sequence uint32
		if json.Unmarshal(request[0], &op) != nil || json.Unmarshal(request[1], &sequence) != nil {
			return
		}
		var response any
		switch op {
		case 1:
			var resource string
			if json.Unmarshal(request[2], &resource) != nil {
				return
			}
			s.mu.Lock()
			fault := s.fault("rta.subscribe", nil)
			if fault != nil && fault.Reset {
				s.steps = append(s.steps, fmt.Sprintf("RTA subscribe %s -> reset", resource))
				s.mu.Unlock()
				return
			}
			s.steps = append(s.steps, fmt.Sprintf("RTA subscribe %s -> connection=%d", resource, connection))
			s.mu.Unlock()
			nextSubscription++
			response = []any{1, sequence, 0, 100*connection + nextSubscription, map[string]any{"ConnectionId": fmt.Sprintf("00000000-0000-0000-0000-%012d", connection)}}
		case 2:
			response = []any{2, sequence, 0}
		default:
			return
		}
		bytes, _ := json.Marshal(response)
		if writeRTAFrame(conn, 1, bytes) != nil {
			return
		}
	}
}

// writeRTAFrame writes one unmasked final server frame and its complete payload.
func writeRTAFrame(w io.Writer, opcode byte, payload []byte) error {
	header := []byte{128 | opcode}
	if len(payload) < 126 {
		header = append(header, byte(len(payload)))
	} else {
		header = append(header, 126, byte(len(payload)>>8), byte(len(payload)))
	}
	_, err := w.Write(append(header, payload...))
	return err
}
