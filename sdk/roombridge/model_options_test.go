package roombridge

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestProtectionModelsWireVersions(t *testing.T) {
	now := time.Unix(1800000000, 0)
	key := []byte(strings.Repeat("k", 32))
	body := []byte(`{"model":"source/gpt-6-astra"}`)
	claims := Claims{Version: 1, RoomID: "room", AccountID: "account", Prefix: "source", AuthIndex: "index", Model: "gpt-6-astra", Enabled: true, RequestID: "request", PolicyVersion: 1}
	headers, err := Sign(key, claims, body, now)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := base64.RawURLEncoding.DecodeString(headers.Get(ClaimsHeader))
	for _, tc := range []struct {
		name    string
		version int
		models  string
		valid   bool
	}{
		{"legacy", 1, "", true}, {"legacy-null", 1, "null", false}, {"legacy-extra", 1, "[]", false},
		{"missing", 2, "", false}, {"null", 2, "null", false}, {"empty", 2, "[]", true},
		{"both", 2, `["gpt-6-astra","gpt-5.6-sol"]`, true}, {"sol", 2, `["gpt-5.6-sol"]`, true},
		{"unknown", 2, `["gpt-6-sol"]`, false}, {"duplicate", 2, `["gpt-6-astra","gpt-6-astra"]`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fields := map[string]json.RawMessage{}
			_ = json.Unmarshal(raw, &fields)
			fields["version"], _ = json.Marshal(tc.version)
			if tc.models != "" {
				fields["protection_models"] = json.RawMessage(tc.models)
			}
			encoded, _ := json.Marshal(fields)
			wire := base64.RawURLEncoding.EncodeToString(encoded)
			h := headers.Clone()
			h.Set(ClaimsHeader, wire)
			mac := hmac.New(sha256.New, key)
			mac.Write([]byte(wire))
			h.Set(SignatureHeader, hex.EncodeToString(mac.Sum(nil)))
			_, err := Verify(key, h, body, now)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v err=%v", tc.valid, err)
			}
			if tc.valid && tc.version == 2 {
				h.Set(ClaimsHeader, headers.Get(ClaimsHeader))
				if _, err := Verify(key, h, body, now); err == nil {
					t.Fatal("accepted unsigned version/model change")
				}
			}
		})
	}
}
