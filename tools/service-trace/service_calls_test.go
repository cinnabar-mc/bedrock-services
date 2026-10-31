package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/sandertv/gophertunnel/minecraft/auth/authclient"
)

// callTransport confines the oracle to synthetic service outcomes.
type callTransport func(*http.Request) (*http.Response, error)

// RoundTrip uses the test's finite response sequence without contacting an account service.
func (f callTransport) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

// TestServiceCallReplayPolicy pins the upstream resend contract for buffered service requests.
func TestServiceCallReplayPolicy(t *testing.T) {
	for _, tc := range []struct {
		name, method, key, after string
		status, want             int
		replayable               bool
	}{
		{name: "unsafe edge failure", method: "POST", status: 503, want: 1},
		{name: "explicit unavailable refusal", method: "POST", status: 503, after: "0", want: 3},
		{name: "throttle refusal", method: "POST", status: 429, want: 3},
		{name: "read only post", method: "POST", status: 500, replayable: true, want: 3},
		{name: "get", method: "GET", status: 500, want: 3},
		{name: "idempotency key", method: "POST", status: 500, key: "Idempotency-Key", want: 3},
		{name: "alternate key", method: "POST", status: 500, key: "X-Idempotency-Key", want: 3},
		{name: "authorization", method: "GET", status: 401, want: 1},
		{name: "unfittable wait", method: "GET", status: 503, after: "60", want: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				calls := 0
				client := &http.Client{Transport: callTransport(func(req *http.Request) (*http.Response, error) {
					calls++
					body, err := io.ReadAll(req.Body)
					if err != nil || string(body) != "original" {
						t.Fatalf("body = %q, %v", body, err)
					}
					header := make(http.Header)
					if tc.after != "" {
						header.Set("Retry-After", tc.after)
					}
					return &http.Response{StatusCode: tc.status, Header: header, Body: io.NopCloser(strings.NewReader(""))}, nil
				})}
				resp, err := authclient.Call(context.Background(), client, func(ctx context.Context) (*http.Request, error) {
					req, err := http.NewRequestWithContext(ctx, tc.method, "https://fixture.invalid/service", strings.NewReader("original"))
					if tc.key != "" {
						req.Header.Set(tc.key, "key")
					}
					return req, err
				}, authclient.CallOptions{Retry: authclient.RetryOptions{Replayable: tc.replayable}})
				if err != nil {
					t.Fatal(err)
				}
				defer resp.Body.Close()
				if calls != tc.want || resp.StatusCode != tc.status {
					t.Fatalf("calls=%d status=%d", calls, resp.StatusCode)
				}
			})
		})
	}
}

// TestServiceCallPreparationDeadline measures the upstream cutoff without a wall-clock wait.
func TestServiceCallPreparationDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		started := time.Now()
		_, err := authclient.Call(context.Background(), nil, func(ctx context.Context) (*http.Request, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		}, authclient.CallOptions{})
		if !errors.Is(err, context.DeadlineExceeded) || time.Since(started) != 40*time.Second {
			t.Fatalf("elapsed=%v err=%v", time.Since(started), err)
		}
	})
}
