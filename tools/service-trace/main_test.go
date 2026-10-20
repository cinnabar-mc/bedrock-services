package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/cinnabar-mc/bedrock-services/tools/service-trace/fake"
	"github.com/df-mc/go-playfab/v2"
	"github.com/df-mc/go-xsapi/v2"
	"github.com/df-mc/go-xsapi/v2/mpsd"
	"github.com/df-mc/go-xsapi/v2/presence"
	"github.com/df-mc/go-xsapi/v2/rta"
	"github.com/df-mc/go-xsapi/v2/xal/nsal"
	"github.com/df-mc/go-xsapi/v2/xal/sisu"
	"github.com/df-mc/go-xsapi/v2/xal/xasd"
	"github.com/sandertv/gophertunnel/minecraft/auth"
	"github.com/sandertv/gophertunnel/minecraft/service"
	"golang.org/x/oauth2"
)

var update = flag.Bool("update", false, "rewrite testdata/*.trace from the Go libraries")

// phaseEnv carries one phase's spec to a child test process, so every phase
// after a restart starts with empty process-wide caches, as a relaunch would.
const phaseEnv = "SERVICE_TRACE_PHASE"

type phaseSpec struct {
	Scenario string
	Phase    int
	StateIn  string
	Out      string
}

// persisted is what a Go client using these libraries can save across restarts.
type persisted struct {
	Elapsed   time.Duration
	Peer      fake.State
	MSA       *oauth2.Token
	ProofKey  []byte
	Device    *xasd.Token
	Snapshot  *sisu.Snapshot
	Service   *service.Token
	SessionID string
}

type phaseResult struct {
	Lines []string
	State persisted
}

// Each golden is the Go libraries' trace for one scenario plan; Rust replays the
// plan from the golden and compares its own trace.
func TestGoldens(t *testing.T) {
	want := map[string]bool{}
	for _, sc := range fake.Scenarios {
		want[sc.Name+".trace"] = true
		t.Run(sc.Name, func(t *testing.T) {
			lines := []string{"# " + sc.Name + ": " + sc.Note}
			state := ""
			for i := range phases(sc.Plan) {
				if i > 0 {
					lines = append(lines, "> restart", "= ok")
				}
				out := filepath.Join(t.TempDir(), "phase.json")
				spec, _ := json.Marshal(phaseSpec{Scenario: sc.Name, Phase: i, StateIn: state, Out: out})
				cmd := exec.Command(os.Args[0], "-test.run=^TestPhase$")
				cmd.Env = append(os.Environ(), phaseEnv+"="+string(spec))
				if b, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("phase %d: %v\n%s", i, err, b)
				}
				var res phaseResult
				readJSON(t, out, &res)
				lines = append(lines, res.Lines...)
				state = filepath.Join(t.TempDir(), "state.json")
				writeJSON(t, state, res.State)
			}
			got := strings.Join(lines, "\n") + "\n"
			path := filepath.Join("testdata", sc.Name+".trace")
			if *update {
				if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			b, err := os.ReadFile(path)
			if err != nil || string(b) != got {
				t.Fatalf("golden %s is stale; rerun with -update\n--- want\n%s--- got\n%s", path, b, got)
			}
		})
	}
	files, _ := filepath.Glob(filepath.Join("testdata", "*.trace"))
	for _, f := range files {
		if base := filepath.Base(f); !want[base] && !strings.HasSuffix(base, ".rust.trace") {
			t.Errorf("%s has no scenario", f)
		}
	}
}

// TestPhase runs one phase inside a synctest bubble, so retry backoff and
// clock advances take no real time. It only runs as TestGoldens' child.
func TestPhase(t *testing.T) {
	raw := os.Getenv(phaseEnv)
	if raw == "" {
		t.Skip("runs only as a TestGoldens child process")
	}
	var spec phaseSpec
	if err := json.Unmarshal([]byte(raw), &spec); err != nil {
		t.Fatal(err)
	}
	sc, ok := fake.Lookup(spec.Scenario)
	if !ok {
		t.Fatalf("unknown scenario %q", spec.Scenario)
	}
	synctest.Test(t, func(t *testing.T) {
		start := time.Now()
		srv := fake.New(sc.Script, time.Now)
		d := newDriver(srv)
		if spec.StateIn != "" {
			var st persisted
			readJSON(t, spec.StateIn, &st)
			time.Sleep(st.Elapsed)
			srv.Import(st.Peer)
			d.restore(t, st)
		}
		var res phaseResult
		for _, step := range phases(sc.Plan)[spec.Phase] {
			err := d.run(step)
			res.Lines = append(res.Lines, "> "+step)
			res.Lines = append(res.Lines, srv.Take()...)
			res.Lines = append(res.Lines, outcome(err))
			if err != nil {
				t.Logf("%s: %v", step, err)
			}
		}
		res.State = d.persist(t, time.Since(start))
		d.close()
		// Let request-timeout timers of unclosed error bodies fire before the bubble ends.
		time.Sleep(time.Hour)
		writeJSON(t, spec.Out, res)
	})
}

// phases splits a plan at its restarts.
func phases(plan []string) [][]string {
	out := [][]string{nil}
	for _, step := range plan {
		if step == "restart" {
			out = append(out, nil)
			continue
		}
		out[len(out)-1] = append(out[len(out)-1], step)
	}
	return out
}

// outcome normalizes a step result; SISU error codes are kept because both SDKs expose them.
func outcome(err error) string {
	if err == nil {
		return "= ok"
	}
	var code sisu.ErrorCode
	if errors.As(err, &code) {
		return fmt.Sprintf("= error xerr=0x%X", uint32(code))
	}
	return "= error"
}

// driver holds the long-lived objects a Go client builds from these libraries.
type driver struct {
	ctx              context.Context
	srv              *fake.Server
	tr               *fake.Transport
	client           *http.Client
	conf             auth.Config
	msa              *lastToken
	device           xasd.TokenSource
	session          *sisu.Session
	resolver         *nsal.Resolver
	env              *service.AuthorizationEnvironment
	src              service.TokenSource
	lastService      *service.Token
	resumed          *service.Token
	sessionID        string
	playfab          *playfab.Client
	xbl              *xsapi.Client
	closers          []func() error
	rtaConn          *rta.Conn
	rtaReady         chan error
	rtaSubscriptions []*rta.Subscription
	directory        *mpsd.Client
}

var quiet = slog.New(slog.DiscardHandler)

func newDriver(srv *fake.Server) *driver {
	tr := &fake.Transport{Server: srv}
	http.DefaultTransport = tr
	client := &http.Client{Transport: tr}
	return &driver{ctx: auth.WithContextClient(context.Background(), client), srv: srv, tr: tr, client: client, conf: auth.AndroidConfig}
}

func (d *driver) run(step string) error {
	verb, arg, _ := strings.Cut(step, " ")
	switch verb {
	case "signin":
		da, err := d.conf.DeviceAuth(d.ctx)
		if err != nil {
			return err
		}
		tok, err := d.conf.DeviceAccessToken(d.ctx, da)
		if err != nil {
			return err
		}
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return err
		}
		d.start(tok, nil, key, nil)
		return nil
	case "join":
		return d.join()
	case "presence":
		if d.xbl == nil {
			c, err := xsapi.ClientConfig{HTTPClient: d.client, RTAMode: xsapi.RTADisabled, Logger: quiet}.New(d.ctx, d.session)
			if err != nil {
				return err
			}
			d.xbl = c
		}
		_, err := d.xbl.Presence().Update(d.ctx, presence.TitleRequest{State: presence.StateActive})
		return err
	case "advance":
		seconds, err := strconv.Atoi(arg)
		if err != nil {
			return err
		}
		time.Sleep(time.Duration(seconds) * time.Second)
		return nil
	case "xsts-pair":
		return d.xstsPair(arg)
	case "rta-subscribe":
		return d.subscribeRTA(1)
	case "rta-subscribe-pair":
		return d.subscribeRTA(2)
	case "rta-active":
		return d.activeRTA()
	case "rta-drop":
		return d.dropRTA()
	case "mpsd-join":
		return d.joinDirectory()
	}
	return fmt.Errorf("unknown step %q", step)
}

// start builds the MSA, device and SISU owners around persisted or fresh material.
func (d *driver) start(tok *oauth2.Token, device *xasd.Token, key *ecdsa.PrivateKey, snap *sisu.Snapshot) {
	d.msa = &lastToken{src: d.conf.TokenSource(d.ctx, tok), tok: tok}
	d.device = xasd.ReuseTokenSource(d.conf.Config.Config, device, key)
	d.session = d.conf.New(d.msa, &sisu.SessionConfig{Snapshot: snap, DeviceTokenSource: d.device, HTTPClient: d.client})
	d.resolver = nsal.NewResolver(d.session)
}

// join mirrors the Dialer's authentication prelude, but keeps the NSAL resolver
// and service token source alive across joins and resumes a persisted service
// token after restart: the most caching a long-lived Go client gets.
func (d *driver) join() error {
	if d.env == nil {
		disc, err := service.Default(d.ctx)
		if err != nil {
			return err
		}
		env := new(service.AuthorizationEnvironment)
		if err := disc.Environment(env); err != nil {
			return err
		}
		env.HTTPClient = d.client
		d.env = env
	}
	if d.src == nil {
		if d.resumed != nil {
			d.src = d.env.ResumeTokenSource(lazyTickets{d}, service.TokenConfig{SessionID: d.sessionID}, d.resumed)
		} else {
			m, err := d.env.NewTokenSource(d.ctx, d.resolver, service.TokenSourceConfig{
				HTTPClient: d.client, PlayFab: playfab.ClientConfig{CreateAccount: true, Logger: quiet},
			})
			if err != nil {
				return err
			}
			d.src, d.sessionID = m, m.SessionID()
			d.closers = append(d.closers, m.Close)
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return err
	}
	if _, err := d.env.MultiplayerToken(d.ctx, d.src, &key.PublicKey); err != nil {
		return err
	}
	// The token was just used, so this is a cache read kept for persistence.
	d.lastService, err = d.src.ServiceToken(d.ctx)
	return err
}

// lazyTickets logs in to PlayFab only when a resumed service token must be replaced.
type lazyTickets struct{ d *driver }

func (l lazyTickets) SessionTicket(ctx context.Context) (string, error) {
	d := l.d
	if d.playfab == nil {
		c, err := playfab.LoginWithXbox(ctx, d.env.PlayFabTitleID, d.resolver,
			playfab.ClientConfig{HTTPClient: d.client, CreateAccount: true, Logger: quiet})
		if err != nil {
			return "", err
		}
		d.playfab = c
		d.closers = append(d.closers, c.Close)
	}
	return d.playfab.SessionTicket(ctx)
}

// xstsPair issues two overlapping XSTS requests for one relying party.
func (d *driver) xstsPair(rp string) error {
	var mu sync.Mutex
	arrived, both := 0, make(chan struct{})
	d.tr.Before = func(r *http.Request, body []byte) {
		if r.URL.Host != "xsts.auth.xboxlive.com" || !strings.Contains(string(body), rp) {
			return
		}
		mu.Lock()
		if arrived++; arrived == 2 {
			close(both)
		}
		mu.Unlock()
		select {
		case <-both:
		case <-time.After(time.Second):
		}
	}
	defer func() { d.tr.Before = nil }()
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i := range errs {
		wg.Go(func() { _, errs[i] = d.session.XSTSToken(d.ctx, rp) })
	}
	wg.Wait()
	return errors.Join(errs...)
}

func (d *driver) persist(t *testing.T, elapsed time.Duration) persisted {
	st := persisted{Elapsed: elapsed, Peer: d.srv.Export(), Service: d.lastService, SessionID: d.sessionID}
	if d.session == nil {
		return st
	}
	key, err := x509.MarshalECPrivateKey(d.device.ProofKey())
	if err != nil {
		t.Fatal(err)
	}
	st.MSA, st.ProofKey, st.Snapshot = d.msa.last(), key, d.session.Snapshot()
	if st.Snapshot.UserToken != nil {
		// A user token implies a cached device token, so this sends nothing.
		st.Device, _ = d.device.DeviceToken(d.ctx)
	}
	return st
}

func (d *driver) restore(t *testing.T, st persisted) {
	d.resumed, d.sessionID = st.Service, st.SessionID
	if st.MSA == nil {
		return
	}
	key, err := x509.ParseECPrivateKey(st.ProofKey)
	if err != nil {
		t.Fatal(err)
	}
	d.start(st.MSA, st.Device, key, st.Snapshot)
}

func (d *driver) close() {
	for _, c := range slices.Backward(d.closers) {
		_ = c()
	}
}

// lastToken remembers the newest MSA token so a restart persists rotations.
type lastToken struct {
	mu  sync.Mutex
	src oauth2.TokenSource
	tok *oauth2.Token
}

func (l *lastToken) Token() (*oauth2.Token, error) {
	tok, err := l.src.Token()
	if err == nil {
		l.mu.Lock()
		l.tok = tok
		l.mu.Unlock()
	}
	return tok, err
}

func (l *lastToken) last() *oauth2.Token {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.tok
}

func readJSON(t *testing.T, path string, v any) {
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatal(err)
	}
}

func writeJSON(t *testing.T, path string, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
}
