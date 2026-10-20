package fake

import (
	"strconv"
	"time"
)

// Scenario pairs the peer's script with the client plan both languages run.
// Plans also support rta-subscribe, rta-drop and mpsd-join through the real service owners.
type Scenario struct {
	Name   string
	Note   string
	Script Script
	Plan   []string
}

const realmsRP = "https://pocket.realms.minecraft.net/"

// Scenarios is the shared catalogue; goldens and Rust drivers derive from it.
var Scenarios = []Scenario{
	{
		Name: "rta-rejected-then-interrupted", Note: "a resource rejection remains observable after its sibling's interrupted restoration",
		Script: Script{Faults: []Fault{{Endpoint: "rta.subscribe", Hits: []int{3}, Status: 1}, {Endpoint: "rta.subscribe", Hits: []int{4}, Reset: true}}},
		Plan:   []string{"signin", "rta-subscribe-pair", "rta-drop", "rta-active"},
	},
	{
		Name: "rta-partial-restoration", Note: "one rejected restore retires only that resource and leaves its sibling active",
		Script: Script{Faults: []Fault{{Endpoint: "rta.subscribe", Hits: []int{3}, Status: 1}}},
		Plan:   []string{"signin", "rta-subscribe-pair", "rta-drop", "rta-active"},
	},
	{
		Name: "rta-reconnect-retry", Note: "a refused replacement upgrade retries with backoff and restores its subscription",
		Script: Script{Faults: []Fault{{Endpoint: "rta", Hits: []int{2}, Status: 503}}},
		Plan:   []string{"signin", "rta-subscribe", "rta-drop"},
	},
	{
		Name: "rta-resubscribe-interrupted", Note: "a replacement dropped during subscribe retries without losing the desired handle",
		Script: Script{Faults: []Fault{{Endpoint: "rta.subscribe", Hits: []int{2}, Reset: true}}},
		Plan:   []string{"signin", "rta-subscribe", "rta-drop"},
	},
	{
		Name: "rta-reconnect", Note: "a dropped RTA socket reconnects and restores the desired subscription",
		Plan: []string{"signin", "rta-subscribe", "rta-drop"},
	},
	{
		Name: "mpsd-412", Note: "explicit ETag conflicts replay one stable join intent at most three times",
		Script: Script{Faults: []Fault{{Endpoint: "mpsd.join", Hits: []int{1}, Status: 412, Header: map[string]string{"ETag": "\"raced1\""}},
			{Endpoint: "mpsd.join", Hits: []int{2}, Status: 412, Header: map[string]string{"ETag": "\"raced2\""}}}},
		Plan: []string{"signin", "mpsd-join"},
	},
	{
		Name: "mpsd-412-exhausted", Note: "three explicit conflicts exhaust the stable join",
		Script: Script{Faults: []Fault{{Endpoint: "mpsd.join", Status: 412, Header: map[string]string{"ETag": "\"raced\""}}}},
		Plan:   []string{"signin", "mpsd-join"},
	},
	{
		Name: "mpsd-reconnect", Note: "a joined membership rebinds after RTA reconnect and resubscribe",
		Plan: []string{"signin", "mpsd-join", "rta-drop"},
	},
	{
		Name: "fresh-signin-join", Note: "device-code sign-in, then the first join token",
		Script: Script{PendingPolls: 1},
		Plan:   []string{"signin", "join"},
	},
	{
		Name: "warm-restart-join", Note: "restart from persisted state, then the first join",
		Plan: []string{"signin", "join", "restart", "join"},
	},
	{
		Name: "warm-restart-expiry", Note: "a restarted service token expires while its PlayFab login remains reusable",
		Plan: []string{"signin", "join", "restart", advance(4*time.Hour - 59*time.Second), "join"},
	},
	{
		Name: "later-join", Note: "later joins in the same process reuse every cached credential",
		Plan: []string{"signin", "join", "join", advance(10 * time.Minute), "join"},
	},
	{
		Name: "near-expiry", Note: "service token reused at 61s left, replaced inside the 1-minute margin",
		Plan: []string{"signin", "join", advance(4*time.Hour - 61*time.Second), "join", advance(2 * time.Second), "join"},
	},
	{
		Name: "xsts-token-expired", Note: "401 token_expired evicts only the rejected XSTS token",
		Script: Script{Faults: []Fault{{Endpoint: "presence", Hits: []int{1}, Status: 401,
			Header: map[string]string{"WWW-Authenticate": `token error="token_expired"`}}}},
		Plan: []string{"signin", "presence", "presence"},
	},
	{
		Name: "session-start-401", Note: "session/start rejects the PlayFab ticket on every attempt",
		Script: Script{Faults: []Fault{{Endpoint: "session.start", Attr: "ticket=p1", Status: 401, Body: `{"code":"Unauthorized"}`}}},
		Plan:   []string{"signin", "join", "join"},
	},
	{
		Name: "retry-after", Note: "429/503 with Retry-After on session/start and presence",
		Script: Script{Faults: []Fault{
			{Endpoint: "session.start", Hits: []int{1}, Status: 503, Header: map[string]string{"Retry-After": "1"}},
			{Endpoint: "presence", Hits: []int{1}, Status: 429, Header: map[string]string{"Retry-After": "2"}},
		}},
		Plan: []string{"signin", "join", "join", "presence", "presence"},
	},
	{
		Name: "transient-failure", Note: "5xx on discovery and a connection reset on the mint",
		Script: Script{Faults: []Fault{
			{Endpoint: "discovery", Hits: []int{1}, Status: 500},
			{Endpoint: "mint", Hits: []int{1}, Reset: true},
		}},
		Plan: []string{"signin", "join", "join", "join"},
	},
	{
		Name: "date-skew", Note: "server clock 20h behind the client",
		Script: Script{Skew: -20 * time.Hour},
		Plan:   []string{"signin", "join", "join"},
	},
	{
		Name: "refresh-rotation", Note: "refresh rotates the token, then a response omits it",
		Script: Script{OmitRefresh: []int{2}, Life: Lifetimes{Title: 2 * time.Hour, User: 2 * time.Hour, XSTS: 2 * time.Hour}},
		Plan: []string{"signin", "presence", advance(3 * time.Hour), "presence", advance(3 * time.Hour), "presence",
			advance(3 * time.Hour), "presence"},
	},
	{
		Name: "nsal-current-failure", Note: "NSAL current fails once; Go caches the failure for 15s",
		Script: Script{Faults: []Fault{{Endpoint: "nsal.current", Hits: []int{1}, Status: 503}}},
		Plan:   []string{"signin", "join", "join", advance(16 * time.Second), "join"},
	},
	{
		Name: "xsts-dedup", Note: "two concurrent requests for one relying party",
		Plan: []string{"signin", "join", "xsts-pair " + realmsRP},
	},
	{
		Name: "sisu-errors", Note: "SISU child-not-in-family, then suspended, then success; each after Go's 15s failure cache",
		Script: Script{Faults: []Fault{
			{Endpoint: "sisu", Hits: []int{1}, Status: 401, Header: map[string]string{"X-Err": "2148916238"}},
			{Endpoint: "sisu", Hits: []int{2}, Status: 401, Header: map[string]string{"X-Err": "2148916227"}},
		}},
		Plan: []string{"signin", "join", advance(16 * time.Second), "join", advance(16 * time.Second), "join"},
	},
	{
		Name: "sisu-failure-cache", Note: "a SISU error poisons NSAL current, so Go replays it for 15s without a request",
		Script: Script{Faults: []Fault{{Endpoint: "sisu", Hits: []int{1}, Status: 401, Header: map[string]string{"X-Err": "2148916238"}}}},
		Plan:   []string{"signin", "join", "join", advance(16 * time.Second), "join"},
	},
}

// Lookup returns the named scenario.
func Lookup(name string) (Scenario, bool) {
	for _, s := range Scenarios {
		if s.Name == name {
			return s, true
		}
	}
	return Scenario{}, false
}

func advance(d time.Duration) string { return "advance " + strconv.Itoa(int(d.Seconds())) }
