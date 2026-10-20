// Package fake is a deterministic Microsoft, Xbox, PlayFab and Minecraft
// services peer that records every request as one normalized trace line.
package fake

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Lifetimes are the validity periods the peer grants, measured on its clock.
type Lifetimes struct {
	MSA, Device, Title, User, XSTS, Service, Mint, Entity time.Duration
}

// Fault replaces the normal answer for selected requests to one endpoint.
type Fault struct {
	Endpoint string            // logical endpoint name, see route
	Attr     string            // optional trace attribute the request must carry
	Hits     []int             // 1-based matching requests to answer; empty answers all
	Status   int               // replacement status
	Header   map[string]string // replacement headers
	Body     string            // replacement JSON body
	Reset    bool              // drop the connection without a response
}

// Script is the server-side half of a scenario.
type Script struct {
	Life         Lifetimes
	Skew         time.Duration // server clock minus client clock
	PendingPolls int           // device-code polls answered authorization_pending
	OmitRefresh  []int         // 1-based refresh grants answered without a refresh token
	Faults       []Fault
}

// Reply is one answer, or a connection drop when Reset is set.
type Reply struct {
	Status int
	Header http.Header
	Body   []byte
	Reset  bool
}

// State is the peer memory a restarted Go process must carry over.
type State struct {
	Labels    map[string]string // issued secret -> trace label
	Issued    map[string]int    // per-prefix issue counters
	FaultHits []int
	Polls     int
	Refreshes int
}

// Server answers and records requests. Its clock is supplied by the host:
// the Go oracle passes the synctest bubble clock, serve mode a manual clock.
type Server struct {
	mu               sync.Mutex
	script           Script
	now              func() time.Time
	state            State
	steps            []string
	rtaConns         map[io.ReadWriteCloser]bool
	directoryMember  map[string]any
	directoryChanged chan struct{}
}

const (
	userHash     = "uhs-fixture"
	xuid         = "2535400000000001"
	playFabTitle = "20ca2"
	serviceHost  = "authorization.franchise.minecraft-services.net"
	defaultRP    = "http://xboxlive.com"
	playFabRP    = "rp://playfabapi.com/"
)

// New returns a peer for script whose client-side clock is now.
func New(script Script, now func() time.Time) *Server {
	d := DefaultLifetimes()
	l := &script.Life
	for _, f := range []struct {
		v *time.Duration
		d time.Duration
	}{
		{&l.MSA, d.MSA}, {&l.Device, d.Device}, {&l.Title, d.Title}, {&l.User, d.User},
		{&l.XSTS, d.XSTS}, {&l.Service, d.Service}, {&l.Mint, d.Mint}, {&l.Entity, d.Entity},
	} {
		if *f.v == 0 {
			*f.v = f.d
		}
	}
	return &Server{script: script, now: now, state: State{
		Labels: map[string]string{}, Issued: map[string]int{}, FaultHits: make([]int, len(script.Faults)),
	}}
}

// DefaultLifetimes approximates retail lifetimes while staying short of the
// 23h40m point where the PlayFab client refreshes entity tokens on its own.
func DefaultLifetimes() Lifetimes {
	return Lifetimes{
		MSA: time.Hour, Device: 14 * 24 * time.Hour, Title: 16 * time.Hour, User: 16 * time.Hour,
		XSTS: 16 * time.Hour, Service: 4 * time.Hour, Mint: time.Hour, Entity: 48 * time.Hour,
	}
}

// Time is the peer's clock, which differs from the client's by the script skew.
func (s *Server) Time() time.Time { return s.now().Add(s.script.Skew).UTC() }

// Export returns the memory a restarted client process must share with its peer.
func (s *Server) Export() State {
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.state
	state.Labels = maps.Clone(state.Labels)
	state.Issued = maps.Clone(state.Issued)
	state.FaultHits = slices.Clone(state.FaultHits)
	return state
}

// Import restores memory exported by an earlier process.
func (s *Server) Import(state State) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state = state
}

// Take returns and clears the trace lines recorded since the last call.
func (s *Server) Take() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	steps := s.steps
	s.steps = nil
	return steps
}

// Handle answers one request; body is the complete request body.
func (s *Server) Handle(method, host string, u *url.URL, header http.Header, body []byte) Reply {
	s.mu.Lock()
	defer s.mu.Unlock()
	host = strings.ToLower(strings.Split(host, ":")[0])
	endpoint := route(method, host, u.Path)
	attrs := s.attrs(endpoint, header, body)
	reply := s.fault(endpoint, attrs)
	if reply == nil {
		r := s.answer(endpoint, header, body)
		reply = &r
	}
	if reply.Header == nil {
		reply.Header = http.Header{}
	}
	reply.Header.Set("Date", s.Time().Format(http.TimeFormat))
	path := u.Path
	if endpoint == "discovery" {
		path = path[:strings.LastIndex(path, "/")+1] + "*"
	}
	if u.RawQuery != "" {
		path += "?" + u.RawQuery
	}
	line := strings.Join(append([]string{method, host + path}, attrs...), " ")
	if reply.Reset {
		line += " -> reset"
	} else {
		line += " -> " + strconv.Itoa(reply.Status)
	}
	s.steps = append(s.steps, line)
	return *reply
}

// route names the logical endpoint used by scripts and attribute extraction.
func route(method, host, path string) string {
	if endpoint := isDirectory(host, path); endpoint != "" {
		return endpoint
	}
	switch {
	case host == "login.live.com" && path == "/oauth20_connect.srf":
		return "oauth.device"
	case host == "login.live.com" && path == "/oauth20_token.srf":
		return "oauth.token"
	case host == "device.auth.xboxlive.com" && path == "/device/authenticate":
		return "device"
	case host == "title.mgt.xboxlive.com" && path == "/titles/default/endpoints":
		return "nsal.default"
	case host == "title.mgt.xboxlive.com" && path == "/titles/current/endpoints":
		return "nsal.current"
	case host == "sisu.xboxlive.com" && path == "/authorize":
		return "sisu"
	case host == "xsts.auth.xboxlive.com" && path == "/xsts/authorize":
		return "xsts"
	case host == "client.discovery.minecraft-services.net" && strings.HasPrefix(path, "/api/v1.0/discovery/MinecraftPE/builds/"):
		return "discovery"
	case host == playFabTitle+".playfabapi.com" && path == "/Client/LoginWithXbox":
		return "playfab.login"
	case host == playFabTitle+".playfabapi.com" && path == "/Authentication/GetEntityToken":
		return "playfab.entity"
	case host == serviceHost && path == "/api/v1.0/session/start":
		return "session.start"
	case host == serviceHost && path == "/api/v1.0/multiplayer/session/start":
		return "mint"
	case host == "userpresence.xboxlive.com" && strings.HasSuffix(path, "/devices/current/titles/current") && method == http.MethodPost:
		return "presence"
	case host == "rta.xboxlive.com" && path == "/connect":
		return "rta"
	}
	return "unknown"
}

// attrs extracts the cache-relevant identity of a request: which credential it
// carries and which grant or relying party it asks for.
func (s *Server) attrs(endpoint string, header http.Header, body []byte) []string {
	var attrs []string
	add := func(key, secret string) {
		if secret != "" {
			attrs = append(attrs, key+"="+s.label(secret))
		}
	}
	if auth := header.Get("Authorization"); auth != "" {
		if _, token, ok := strings.Cut(auth, ";"); ok && strings.HasPrefix(auth, "XBL3.0 ") {
			add("auth", token)
		} else {
			add("auth", auth)
		}
	}
	var fields map[string]any
	_ = json.Unmarshal(body, &fields)
	text := func(key string) string { v, _ := fields[key].(string); return v }
	switch endpoint {
	case "mpsd.join", "mpsd.update":
		attrs = append(attrs, s.directoryAttrs(endpoint, header, body)...)
	case "oauth.token":
		form, _ := url.ParseQuery(string(body))
		grant := form.Get("grant_type")
		attrs = append(attrs, "grant="+strings.TrimPrefix(grant, "urn:ietf:params:oauth:grant-type:"))
		add("refresh", form.Get("refresh_token"))
	case "sisu":
		add("access", strings.TrimPrefix(text("AccessToken"), "t="))
	case "xsts":
		attrs = append(attrs, "rp="+text("RelyingParty"))
	case "playfab.login":
		if _, token, ok := strings.Cut(text("XboxToken"), ";"); ok {
			add("xbox", token)
		}
	case "playfab.entity":
		add("entity", header.Get("X-EntityToken"))
	case "session.start":
		user, _ := fields["user"].(map[string]any)
		ticket, _ := user["token"].(string)
		add("ticket", ticket)
	}
	if header.Get("Signature") != "" {
		attrs = append(attrs, "signed")
	}
	return attrs
}

// label names a secret this peer issued, or "?" for one it never issued.
func (s *Server) label(secret string) string {
	if l, ok := s.state.Labels[secret]; ok {
		return l
	}
	return "?"
}

// issue mints a secret whose trace label is prefix plus a per-prefix counter.
func (s *Server) issue(prefix string) string {
	s.state.Issued[prefix]++
	l := prefix + strconv.Itoa(s.state.Issued[prefix])
	s.state.Labels[l] = l
	return l
}

// fault returns the first scripted replacement for this request, if any. Every
// matching fault counts the request, so Hits number requests, not misses.
func (s *Server) fault(endpoint string, attrs []string) *Reply {
	var chosen *Fault
	for i := range s.script.Faults {
		f := &s.script.Faults[i]
		if f.Endpoint != endpoint || (f.Attr != "" && !slices.Contains(attrs, f.Attr)) {
			continue
		}
		s.state.FaultHits[i]++
		if chosen == nil && (len(f.Hits) == 0 || slices.Contains(f.Hits, s.state.FaultHits[i])) {
			chosen = f
		}
	}
	if f := chosen; f != nil {
		r := &Reply{Status: f.Status, Header: http.Header{}, Body: []byte(f.Body), Reset: f.Reset}
		for k, v := range f.Header {
			r.Header.Set(k, v)
		}
		return r
	}
	return nil
}

// answer produces the normal successful response for endpoint.
func (s *Server) answer(endpoint string, header http.Header, body []byte) Reply {
	now := s.Time()
	l := s.script.Life
	stamp := func(d time.Duration) string { return now.Add(d).Format(time.RFC3339) }
	token := func(prefix string, d time.Duration, claims any) map[string]any {
		return map[string]any{"IssueInstant": stamp(0), "NotAfter": stamp(d), "Token": s.issue(prefix), "DisplayClaims": claims}
	}
	user := map[string]any{"xui": []any{map[string]any{"uhs": userHash}}}
	switch endpoint {
	case "rta":
		return upgradeReply(header)
	case "mpsd.join", "mpsd.update":
		return s.directoryReply(body)
	case "mpsd.activity":
		return reply(201, map[string]any{"id": "00000000-0000-0000-0000-000000000010"})
	case "oauth.device":
		return reply(200, map[string]any{"device_code": s.issue("dc"), "user_code": "FIXTURE",
			"verification_uri": "https://www.microsoft.com/link", "expires_in": 900, "interval": 5})
	case "oauth.token":
		form, _ := url.ParseQuery(string(body))
		switch form.Get("grant_type") {
		case "urn:ietf:params:oauth:grant-type:device_code":
			s.state.Polls++
			if s.state.Polls <= s.script.PendingPolls {
				return reply(400, map[string]any{"error": "authorization_pending"})
			}
		case "refresh_token":
			if s.label(form.Get("refresh_token")) == "?" {
				return reply(400, map[string]any{"error": "invalid_grant"})
			}
			s.state.Refreshes++
			if slices.Contains(s.script.OmitRefresh, s.state.Refreshes) {
				return reply(200, map[string]any{"token_type": "bearer", "scope": "service::user.auth.xboxlive.com::MBI_SSL",
					"expires_in": int(l.MSA.Seconds()), "access_token": s.issue("a")})
			}
		}
		return reply(200, map[string]any{"token_type": "bearer", "scope": "service::user.auth.xboxlive.com::MBI_SSL",
			"expires_in": int(l.MSA.Seconds()), "access_token": s.issue("a"), "refresh_token": s.issue("r"), "user_id": "fixture"})
	case "device":
		return reply(200, token("d", l.Device, map[string]any{"xdi": map[string]any{"did": "F70000000FIXTURE", "dcs": "0"}}))
	case "nsal.default":
		return reply(200, map[string]any{
			"EndPoints": []any{
				map[string]any{"Protocol": "https", "Host": "*.xboxlive.com", "HostType": "wildcard", "RelyingParty": defaultRP, "TokenType": "JWT", "SignaturePolicyIndex": 0},
			},
			"SignaturePolicies": []any{map[string]any{"Version": 1, "SupportedAlgorithms": []string{"ES256"}, "MaxBodyBytes": 8192}},
		})
	case "nsal.current":
		return reply(200, map[string]any{
			"EndPoints": []any{
				map[string]any{"Protocol": "https", "Host": playFabTitle + ".playfabapi.com", "HostType": "fqdn", "RelyingParty": playFabRP, "TokenType": "JWT"},
			},
			"SignaturePolicies": []any{},
		})
	case "sisu":
		return reply(200, map[string]any{
			"DeviceToken": "", "Sandbox": "RETAIL", "UseModernGamertag": true,
			"TitleToken": token("t", l.Title, map[string]any{"xti": map[string]any{"tid": "1739947436"}}),
			"UserToken":  token("u", l.User, user),
			"AuthorizationToken": token("x", l.XSTS, map[string]any{"xui": []any{map[string]any{
				"uhs": userHash, "xid": xuid, "gtg": "Fixture", "agg": "Adult", "usr": "", "utr": "", "prv": ""}}}),
		})
	case "xsts":
		return reply(200, token("x", l.XSTS, user))
	case "discovery":
		uri := "https://" + serviceHost
		return reply(200, map[string]any{"result": map[string]any{
			"serviceEnvironments": map[string]any{"auth": map[string]any{"prod": map[string]any{
				"serviceUri": uri, "issuer": uri, "playFabTitleId": strings.ToUpper(playFabTitle), "eduPlayFabTitleId": "6955F"}}},
			"supportedEnvironments": map[string]any{},
		}})
	case "playfab.login":
		return reply(200, map[string]any{"code": 200, "status": "OK", "data": map[string]any{
			"SessionTicket": s.issue("p"), "PlayFabId": "PLAYFAB1", "NewlyCreated": false,
			"EntityToken": map[string]any{"EntityToken": s.issue("e"), "TokenExpiration": stamp(l.Entity),
				"Entity": map[string]any{"Id": "TITLEPLAYER1", "Type": "title_player_account", "TypeString": "title_player_account"}},
		}})
	case "playfab.entity":
		var req struct{ Entity struct{ Id, Type string } }
		_ = json.Unmarshal(body, &req)
		return reply(200, map[string]any{"code": 200, "status": "OK", "data": map[string]any{
			"EntityToken": s.issue("e"), "TokenExpiration": stamp(l.Entity),
			"Entity": map[string]any{"Id": req.Entity.Id, "Type": req.Entity.Type, "TypeString": req.Entity.Type}}})
	case "session.start":
		label := s.issue("m")
		claims, _ := json.Marshal(map[string]any{"pmid": "6e8c79a8-58a4-4be6-a78c-9b7c8f2b0c11", "jti": label,
			"iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(l.Service).Unix()})
		value := "MCToken " + b64(`{"alg":"none","typ":"JWT"}`) + "." + b64(string(claims)) + ".fixture"
		s.state.Labels[value] = label
		return reply(200, map[string]any{"result": map[string]any{"authorizationHeader": value,
			"validUntil": stamp(l.Service), "treatments": []string{}, "configurations": map[string]any{}, "treatmentContext": ""}})
	case "mint":
		return reply(200, map[string]any{"result": map[string]any{"signedToken": s.issue("mp"),
			"validUntil": stamp(l.Mint), "issuedAt": stamp(0)}})
	case "presence":
		r := Reply{Status: 200, Header: http.Header{}}
		r.Header.Set("X-Heartbeat-After", "300")
		return r
	}
	return reply(404, map[string]any{"error": "unknown fixture endpoint"})
}

// reply encodes a JSON answer.
func reply(status int, value any) Reply {
	body, err := json.Marshal(value)
	if err != nil {
		panic(fmt.Sprintf("fake: encode reply: %v", err))
	}
	h := http.Header{}
	h.Set("Content-Type", "application/json")
	return Reply{Status: status, Header: h, Body: body}
}

func b64(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
