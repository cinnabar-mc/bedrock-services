package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/df-mc/go-xsapi/v2/social"
	"github.com/df-mc/go-xsapi/v2/xal/xsts"
)

// profileTransport confines profile requests to synthetic responses.
type profileTransport func(*http.Request) (*http.Response, error)

// RoundTrip inspects the upstream request without sending account traffic.
func (f profileTransport) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

// TestProfileSettingsMap pins arbitrary keys, boolean strings and comma-separated platforms.
func TestProfileSettingsMap(t *testing.T) {
	settings := make(social.ProfileSettings)
	if err := json.Unmarshal([]byte(`{"settings":[{"userSetting":{"id":"FutureSetting","value":"opaque"}},{"userSetting":{"id":"Bio","value":"before"}},{"userSetting":{"id":"Bio","value":"after"}}]}`), &settings); err != nil {
		t.Fatal(err)
	}
	changed := settings.WithShowUserAsAvatar(true).WithPreferredPlatforms([]string{"pc", "future"})
	if settings["ShowUserAsAvatar"] != "" || changed["Bio"] != "after" || changed["FutureSetting"] != "opaque" || !changed.ShowUserAsAvatar() || strings.Join(changed.PreferredPlatforms(), ",") != "pc,future" {
		t.Fatal("map conventions changed")
	}
	encoded, err := json.Marshal(changed)
	if err != nil {
		t.Fatal(err)
	}
	decoded := make(social.ProfileSettings)
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["FutureSetting"] != "opaque" || decoded.WithShowUserAsAvatar(false)["ShowUserAsAvatar"] != "0" {
		t.Fatal("map round trip lost settings")
	}
}

// TestUpdateProfileSettingsRequest pins the actual upstream contract and one-dispatch status rule.
func TestUpdateProfileSettingsRequest(t *testing.T) {
	for _, status := range []int{201, 503, 200} {
		calls := 0
		client := social.New(&http.Client{Transport: profileTransport(func(req *http.Request) (*http.Response, error) {
			calls++
			if req.Method != "POST" || req.URL.String() != "https://profile.xboxlive.com/users/me/profile/settings/batch" || req.Header.Get("X-Xbl-Contract-Version") != "3" || req.Header.Get("Content-Type") != "application/json" {
				t.Fatal("profile request contract changed")
			}
			body, err := io.ReadAll(req.Body)
			if err != nil || !strings.Contains(string(body), `"FutureSetting"`) {
				t.Fatalf("settings body: %v", err)
			}
			return &http.Response{Request: req, Status: http.StatusText(status), StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(""))}, nil
		})}, nil, xsts.UserInfo{}, nil)
		err := client.UpdateProfileSettings(context.Background(), social.ProfileSettings{"FutureSetting": "opaque"})
		if calls != 1 || (err == nil) != (status == 201) {
			t.Fatalf("status=%d calls=%d success=%v", status, calls, err == nil)
		}
	}
}
