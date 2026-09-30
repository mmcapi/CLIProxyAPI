// Package roombridge authenticates room-scoped optimization execution decisions.
package roombridge

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
)

const ClaimsHeader = "X-MMC-Optimization"
const SignatureHeader = "X-MMC-Optimization-Signature"
const KeyEnv = "MMC_OPTIMIZATION_BRIDGE_KEY"
const MaxHeaderBytes = 8192

type Claims struct {
	Version          int       `json:"version"`
	RoomID           string    `json:"room_id"`
	AccountID        string    `json:"account_id"`
	Prefix           string    `json:"prefix"`
	AuthIndex        string    `json:"auth_index"`
	Model            string    `json:"model"`
	Enabled          bool      `json:"enabled"`
	AutoDisableOn403 bool      `json:"auto_disable_on_403"`
	ExpiresAt        int64     `json:"expires_at"`
	BodySHA256       string    `json:"body_sha256"`
	RequestID        string    `json:"request_id"`
	PolicyVersion    int64     `json:"policy_version"`
	ProtectionModels *[]string `json:"protection_models,omitempty"`
}

var errInvalid = errors.New("invalid optimization execution proof")

// Present detects either header, including malformed case variants and empty values.
func Present(headers http.Header) bool {
	for name := range headers {
		if strings.EqualFold(name, ClaimsHeader) || strings.EqualFold(name, SignatureHeader) {
			return true
		}
	}
	return false
}

func singleHeader(headers http.Header, name string) (string, error) {
	var values []string
	for k, v := range headers {
		if strings.EqualFold(k, name) {
			values = append(values, v...)
		}
	}
	if len(values) != 1 || len(values[0]) == 0 || len(values[0]) > MaxHeaderBytes {
		return "", errInvalid
	}
	return values[0], nil
}

// Sign binds a decision to the exact request body. Callers supply a unique request ID.
func Sign(key []byte, claims Claims, body []byte, now time.Time) (http.Header, error) {
	if len(key) < 32 {
		return nil, errInvalid
	}
	if claims.ExpiresAt == 0 {
		claims.ExpiresAt = now.Unix() + 30
	}
	digest := sha256.Sum256(body)
	claims.BodySHA256 = hex.EncodeToString(digest[:])
	if err := validate(claims, body, now); err != nil {
		return nil, err
	}
	data, err := json.Marshal(claims)
	if err != nil {
		return nil, err
	}
	raw := base64.RawURLEncoding.EncodeToString(data)
	if len(raw) > MaxHeaderBytes {
		return nil, errInvalid
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(raw))
	headers := make(http.Header)
	headers.Set(ClaimsHeader, raw)
	headers.Set(SignatureHeader, hex.EncodeToString(mac.Sum(nil)))
	return headers, nil
}

// Verify rejects unsigned, stale, malformed, or differently bound decisions.
func Verify(key []byte, headers http.Header, body []byte, now time.Time) (Claims, error) {
	var claims Claims
	if len(key) < 32 {
		return claims, errInvalid
	}
	raw, err := singleHeader(headers, ClaimsHeader)
	if err != nil {
		return claims, err
	}
	sig, err := singleHeader(headers, SignatureHeader)
	if err != nil {
		return claims, err
	}
	if len(sig) != 64 || sig != strings.ToLower(sig) {
		return claims, errInvalid
	}
	decodedSig, err := hex.DecodeString(sig)
	if err != nil {
		return claims, errInvalid
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(raw))
	if !hmac.Equal(decodedSig, mac.Sum(nil)) {
		return claims, errInvalid
	}
	data, err := base64.RawURLEncoding.Strict().DecodeString(raw)
	if err != nil {
		return claims, errInvalid
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if dec.Decode(&claims) != nil {
		return Claims{}, errInvalid
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(data, &fields) != nil {
		return Claims{}, errInvalid
	}
	if _, present := fields["protection_models"]; claims.Version == 1 && present {
		return Claims{}, errInvalid
	}
	var trailing any
	if dec.Decode(&trailing) != io.EOF {
		return Claims{}, errInvalid
	}
	if err := validate(claims, body, now); err != nil {
		return Claims{}, err
	}
	return claims, nil
}

func validate(c Claims, body []byte, now time.Time) error {
	if (c.Version != 1 && c.Version != 2) || c.PolicyVersion < 1 || c.ExpiresAt <= now.Unix() || c.ExpiresAt > now.Unix()+60 {
		return errInvalid
	}
	if c.Version == 1 && c.ProtectionModels != nil {
		return errInvalid
	}
	if c.Version == 2 && (c.ProtectionModels == nil || !ValidProtectionModels(*c.ProtectionModels)) {
		return errInvalid
	}
	for _, v := range []string{c.RoomID, c.AccountID, c.Prefix, c.AuthIndex, c.Model, c.RequestID} {
		if v == "" || len(v) > 256 || strings.TrimSpace(v) != v || strings.ContainsAny(v, "\r\n\x00") {
			return errInvalid
		}
	}
	if strings.Contains(c.Prefix, "/") || strings.Contains(c.Model, "/") {
		return errInvalid
	}
	if c.Enabled && c.Model != "gpt-6-astra" && c.Model != "gpt-6-sol" && c.Model != "gpt-5.6-sol" {
		return errInvalid
	}
	digest := sha256.Sum256(body)
	if c.BodySHA256 != hex.EncodeToString(digest[:]) {
		return errInvalid
	}
	var input struct {
		Model string `json:"model"`
	}
	if json.Unmarshal(body, &input) != nil || input.Model != c.Prefix+"/"+c.Model {
		return errInvalid
	}
	return nil
}

// ValidProtectionModels requires an explicit array containing supported, unique models.
func ValidProtectionModels(models []string) bool {
	if models == nil {
		return false
	}
	seen := make(map[string]bool, len(models))
	for _, model := range models {
		if (model != "gpt-6-astra" && model != "gpt-5.6-sol") || seen[model] {
			return false
		}
		seen[model] = true
	}
	return true
}
