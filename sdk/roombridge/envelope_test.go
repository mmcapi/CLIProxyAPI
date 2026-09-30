package roombridge

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestEnvelope(t *testing.T) {
	now := time.Unix(1800000000, 0)
	key := []byte(strings.Repeat("k", 32))
	body := []byte(`{"model":"room-source/gpt-6-astra"}`)
	claims := Claims{Version: 1, RoomID: "room", AccountID: "account", Prefix: "room-source", AuthIndex: "index", Model: "gpt-6-astra", Enabled: true, ExpiresAt: now.Unix() + 30, RequestID: "unique-request", PolicyVersion: 1}
	headers, err := Sign(key, claims, body, now)
	if err != nil {
		t.Fatal(err)
	}
	if headers.Get(SignatureHeader) != "4c719a6884a54eb4046461543790ae600b48701edc1bbf84a274f0df38862361" {
		t.Fatal("wire golden signature changed")
	}
	got, err := Verify(key, headers, body, now)
	if err != nil || got.RoomID != claims.RoomID {
		t.Fatalf("verify: %+v %v", got, err)
	}
	for _, tc := range []struct {
		name    string
		headers http.Header
		body    []byte
		now     time.Time
	}{
		{"missing", http.Header{}, body, now},
		{"body", headers, []byte(`{"model":"other/gpt-6-astra"}`), now},
		{"expired", headers, body, now.Add(time.Minute)},
		{"future", headers, body, now.Add(-time.Minute)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Verify(key, tc.headers, tc.body, tc.now); err == nil {
				t.Fatal("accepted invalid envelope")
			}
		})
	}
	bad := headers.Clone()
	bad.Set(SignatureHeader, strings.Repeat("0", 64))
	if _, err := Verify(key, bad, body, now); err == nil {
		t.Fatal("accepted invalid signature")
	}
	bad = headers.Clone()
	bad.Add(ClaimsHeader, bad.Get(ClaimsHeader))
	if _, err := Verify(key, bad, body, now); err == nil {
		t.Fatal("accepted duplicate header")
	}
	bad = headers.Clone()
	bad.Set(ClaimsHeader, strings.Repeat("a", 8193))
	if _, err := Verify(key, bad, body, now); err == nil {
		t.Fatal("accepted oversized header")
	}
	claims.Model = "gpt-unknown"
	if _, err := Sign(key, claims, []byte(`{"model":"room-source/gpt-unknown"}`), now); err == nil {
		t.Fatal("accepted unsupported enabled model")
	}
	claims.Model = "gpt-6-astra"
	if _, err := Sign(key, claims, []byte(`{"model":"wrong/gpt-6-astra"}`), now); err == nil {
		t.Fatal("accepted wrong model binding")
	}
	if _, err := Verify([]byte("weak"), headers, body, now); err == nil {
		t.Fatal("accepted short key")
	}
	claims.Model = "gpt-5.6-sol"
	if _, err := Sign(key, claims, []byte(`{"model":"room-source/gpt-5.6-sol"}`), now); err != nil {
		t.Fatal("existing sol model rejected:", err)
	}
}
