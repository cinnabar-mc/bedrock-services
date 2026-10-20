package fake

import (
	"strconv"
	"time"
)

// Scenario pairs the peer's script with the client plan both languages run.
// Plan steps: signin, join, presence, restart, advance <seconds>, xsts-pair <relying party>.
type Scenario struct {
	Name        string
	Note        string
	Script      Script
	Plan        []string
	CachedRoute bool
}

const realmsRP = "https://pocket.realms.minecraft.net/"

// Scenarios is the shared catalogue; goldens and Rust drivers derive from it.
var Scenarios = []Scenario{
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
		Name: "warm-restart-cached-route", Note: "restart with a version-bound auth route and a reusable service token",
		Plan:        []string{"signin", "join", "restart", "join"},
		CachedRoute: true,
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
