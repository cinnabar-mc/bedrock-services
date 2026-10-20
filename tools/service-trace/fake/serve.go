package fake

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"sync"
	"syscall"
	"time"
)

// Transport answers requests in process, so the Go oracle's clock can be a
// synctest bubble. A reset reply surfaces as a connection-reset error.
type Transport struct {
	Server *Server
	// Before runs ahead of each request; the oracle uses it to overlap requests.
	Before func(*http.Request, []byte)
}

// RoundTrip implements http.RoundTripper.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	var body []byte
	if req.Body != nil {
		var err error
		if body, err = io.ReadAll(req.Body); err != nil {
			return nil, err
		}
		_ = req.Body.Close()
	}
	if t.Before != nil {
		t.Before(req, body)
	}
	r := t.Server.Handle(req.Method, req.URL.Host, req.URL, req.Header, body)
	if r.Reset {
		return nil, &net.OpError{Op: "read", Net: "tcp", Err: syscall.ECONNRESET}
	}
	return &http.Response{
		Status: fmt.Sprintf("%d %s", r.Status, http.StatusText(r.Status)), StatusCode: r.Status,
		Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1, Header: r.Header,
		Body: io.NopCloser(bytes.NewReader(r.Body)), ContentLength: int64(len(r.Body)), Request: req,
	}, nil
}

// ServeHTTP answers a request received over TLS; resets close the socket with RST.
func (s *Server) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	body, err := io.ReadAll(req.Body)
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}
	r := s.Handle(req.Method, req.Host, req.URL, req.Header, body)
	if r.Reset {
		conn, _, err := http.NewResponseController(w).Hijack()
		if err == nil {
			if t, ok := conn.(*tls.Conn); ok {
				if tcp, ok := t.NetConn().(*net.TCPConn); ok {
					_ = tcp.SetLinger(0)
				}
			}
			_ = conn.Close()
		}
		return
	}
	for k, v := range r.Header {
		w.Header()[k] = v
	}
	w.WriteHeader(r.Status)
	_, _ = w.Write(r.Body)
}

// Serve runs the shared peer for out-of-process clients. Requests and replies
// on in/out are JSON objects, each prefixed by a 4-byte big-endian length.
// Each "open" starts an isolated scenario peer on its own loopback TLS port.
func Serve(in io.Reader, out io.Writer) error {
	ca, err := newAuthority()
	if err != nil {
		return err
	}
	var (
		mu       sync.Mutex
		sessions = map[int]*session{}
		next     int
	)
	r, w := bufio.NewReader(in), bufio.NewWriter(out)
	for {
		var req struct {
			Op       string `json:"op"`
			Session  int    `json:"session"`
			Scenario string `json:"scenario"`
			Seconds  int64  `json:"seconds"`
		}
		if err := readFrame(r, &req); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		var resp any
		mu.Lock()
		s := sessions[req.Session]
		switch {
		case req.Op == "open":
			sc, ok := Lookup(req.Scenario)
			if !ok {
				resp = map[string]any{"error": "unknown scenario " + req.Scenario}
				break
			}
			next++
			s, err = open(sc.Script, ca)
			if err != nil {
				resp = map[string]any{"error": err.Error()}
				break
			}
			sessions[next] = s
			resp = map[string]any{"session": next, "addr": s.ln.Addr().String(), "ca": ca.pem, "now": s.server.Time().Unix()}
		case s == nil:
			resp = map[string]any{"error": "unknown session"}
		case req.Op == "advance":
			s.advance(time.Duration(req.Seconds) * time.Second)
			resp = map[string]any{"now": s.server.Time().Unix()}
		case req.Op == "take":
			steps := s.server.Take()
			if steps == nil {
				steps = []string{}
			}
			resp = map[string]any{"steps": steps}
		case req.Op == "close":
			_ = s.http.Close()
			delete(sessions, req.Session)
			resp = map[string]any{}
		default:
			resp = map[string]any{"error": "unknown op " + req.Op}
		}
		mu.Unlock()
		if err := writeFrame(w, resp); err != nil {
			return err
		}
	}
}

// session is one scenario peer with a manual clock that moves only on advance.
type session struct {
	server *Server
	ln     net.Listener
	http   *http.Server
	mu     sync.Mutex
	clock  time.Time
}

func open(script Script, ca *authority) (*session, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	s := &session{ln: ln, clock: time.Now().UTC().Truncate(time.Second)}
	s.server = New(script, func() time.Time { s.mu.Lock(); defer s.mu.Unlock(); return s.clock })
	s.http = &http.Server{Handler: s.server, TLSConfig: &tls.Config{
		GetCertificate: ca.certificate, NextProtos: []string{"http/1.1"}, MinVersion: tls.VersionTLS12,
	}}
	go func() { _ = s.http.ServeTLS(ln, "", "") }()
	return s, nil
}

func (s *session) advance(d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clock = s.clock.Add(d)
}

// authority issues a leaf certificate for whichever host a client names.
type authority struct {
	cert  *x509.Certificate
	key   *ecdsa.PrivateKey
	pem   string
	mu    sync.Mutex
	leafs map[string]*tls.Certificate
}

func newAuthority() (*authority, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "service-trace fixture CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &authority{cert: cert, key: key, leafs: map[string]*tls.Certificate{},
		pem: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}, nil
}

func (a *authority) certificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	host := hello.ServerName
	if c, ok := a.leafs[host]; ok {
		return c, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(int64(len(a.leafs) + 2)), Subject: pkix.Name{CommonName: host},
		DNSNames: []string{host}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, a.cert, &key.PublicKey, a.key)
	if err != nil {
		return nil, err
	}
	c := &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	a.leafs[host] = c
	return c, nil
}

func readFrame(r io.Reader, v any) error {
	var n uint32
	if err := binary.Read(r, binary.BigEndian, &n); err != nil {
		return err
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return err
	}
	return json.Unmarshal(buf, v)
}

func writeFrame(w *bufio.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if err := binary.Write(w, binary.BigEndian, uint32(len(b))); err != nil {
		return err
	}
	if _, err := w.Write(b); err != nil {
		return err
	}
	return w.Flush()
}
