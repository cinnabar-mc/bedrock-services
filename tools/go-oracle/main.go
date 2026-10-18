// The oracle signs original synthetic requests using the public Go baseline.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"os"
	"time"

	"github.com/df-mc/go-xsapi/v2/xal/nsal"
)

// main emits signatures, not keys or account credentials, for three wire boundaries.
func main() {
	f, err := os.Open(os.Args[1])
	if err != nil {
		panic(err)
	}
	defer f.Close()
	var fixture struct {
		Scalar   int64 `json:"key_scalar"`
		Seconds  int64 `json:"time_unix_seconds"`
		Nanos    int64 `json:"subsecond_nanos"`
		Requests []struct {
			URL, Body string
			Limit     int
			Headers   []string
		}
	}
	if err := json.NewDecoder(f).Decode(&fixture); err != nil {
		panic(err)
	}
	d := big.NewInt(fixture.Scalar)
	x, y := elliptic.P256().ScalarBaseMult(d.Bytes())
	key := &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, D: d}
	timestamp := time.Unix(fixture.Seconds, fixture.Nanos)
	result := make([]string, 0, len(fixture.Requests))
	for _, input := range fixture.Requests {
		req, err := http.NewRequest(http.MethodPost, input.URL, nil)
		if err != nil {
			panic(err)
		}
		req.Header.Set("Authorization", "synthetic-authorization")
		req.Header.Set("X-Extra", "first")
		req.Header.Add("X-Extra", "second")
		policy := nsal.SignaturePolicy{Version: 1, MaxBodyBytes: input.Limit, ExtraHeaders: input.Headers}
		sig, err := policy.Generate(
			req,
			[]byte(input.Body),
			key,
			timestamp,
		)
		if err != nil {
			panic(err)
		}
		result = append(result, base64.StdEncoding.EncodeToString(sig))
	}
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		panic(err)
	}
}
