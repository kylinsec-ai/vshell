// Package utils provides application authentication helpers, role checks, and password hashing.
// Security note: comments describe current behavior, not a claim that these helpers meet production security requirements.
package utils

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

var (
	settings     *Settings
	settingsOnce sync.Once
	settingsMu   sync.RWMutex
)

// Settings contains the authentication-related application configuration.
type Settings struct {
	License      string
	MasterType   string
	WebTitle     string
	WebPort      int
	WebIP        string
	WebBasicAuth bool
	WebUsername  string
	WebPassword  string
	WebJWTSecret string
}

// GetSettings returns the lazily initialized process-wide settings instance.
func GetSettings() *Settings {
	settingsOnce.Do(func() {
		settings = &Settings{
			MasterType:   "web",
			WebTitle:     "管理平台",
			WebPort:      8082,
			WebIP:        "0.0.0.0",
			WebBasicAuth: true,
			WebUsername:  "admin",
			WebPassword:  "", // no hardcoded default — main.go generates a random one at startup
			WebJWTSecret: generateJWTSecret(), // random per process if not overridden
		}
	})
	settingsMu.RLock()
	defer settingsMu.RUnlock()
	return settings
}

// GetJWTSecret returns the configured JWT signing secret.
func GetJWTSecret() string {
	return GetSettings().WebJWTSecret
}

// generateJWTSecret creates a random secret for signing tokens.
func generateJWTSecret() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// JWTClaims contains the claims extracted by the token validation helpers.
// Field presence and validation are determined by the current implementation.
type JWTClaims struct {
	TokenType string `json:"token_type"`
	UserID    string `json:"user_id"`
	RoleID    string `json:"role_id"`
	Username  string `json:"username"`
	Exp       int64  `json:"exp"`
	Iat       int64  `json:"iat"`
}

// Role values used by the application's role checks.
const (
	RoleSuperAdmin = "super"
	RoleAdmin      = "admin"
	RoleUser       = "user"
)

// rolePermissions maps each role to allowed API path prefixes.
// Prefix matching is literal; review route normalization and authorization at call sites.
var rolePermissions = map[string][]string{
	RoleSuperAdmin: {"*"},
	RoleAdmin: {
		"/api/listener/", "/api/client/", "/api/dashboard/",
		"/api/file/", "/api/terminal/", "/api/tunnel/",
		"/api/download/", "/api/install/", "/api/screen/",
		"/api/screenshot/", "/api/runner/", "/api/settings/",
	},
	RoleUser: {
		"/api/dashboard/", "/api/client/list", "/api/client/get",
	},
}

// GetRoleID maps a role value to its string identifier; unknown values map to "0".
func GetRoleID(role string) string {
	switch role {
	case RoleSuperAdmin:
		return "1"
	case RoleAdmin:
		return "2"
	case RoleUser:
		return "3"
	default:
		return "0"
	}
}

// GetRoleName maps a role identifier to a display name.
func GetRoleName(roleID string) string {
	switch roleID {
	case "1":
		return "Super Admin"
	case "2":
		return "Admin"
	case "3":
		return "User"
	default:
		return "Unknown"
	}
}

// HasPermission reports whether a role matches one of its configured path prefixes.
// The super-admin role bypasses this check; callers must authenticate the role first.
func HasPermission(roleValue string, path string) bool {
	if roleValue == RoleSuperAdmin {
		return true
	}
	perms, ok := rolePermissions[roleValue]
	if !ok {
		return false
	}
	for _, prefix := range perms {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

// UserInfoResponse is the response envelope used by the user-info endpoint.
type UserInfoResponse struct {
	Code    int      `json:"code"`
	Message string   `json:"message"`
	Type    string   `json:"type"`
	Result  UserInfo `json:"result"`
}

// UserInfo contains the profile fields returned to the client.
type UserInfo struct {
	Avatar   string         `json:"avatar"`
	UserID   string         `json:"userId"`
	Username string         `json:"username"`
	RealName string         `json:"realName"`
	Desc     string         `json:"desc"`
	HomePath string         `json:"homePath"`
	Roles    []RoleInfoResp `json:"roles"`
	Token    string         `json:"token"`
}

// RoleInfoResp describes a role in the user-info response.
type RoleInfoResp struct {
	RoleName string `json:"roleName"`
	Value    string `json:"value"`
}

// GenerateToken creates a token using the default super-admin identifiers.
// Do not expose this helper to untrusted callers; it does not perform authentication.
func GenerateToken(username string) (string, error) {
	return GenerateTokenWithRoles(username, "1", "1")
}

// GenerateTokenWithRoles serializes the supplied identity and role fields into a signed token.
// Claims are currently assembled with string formatting; callers should not assume arbitrary input
// is safely JSON-escaped. Keep inputs trusted until serialization is replaced with encoding/json.
func GenerateTokenWithRoles(username, userID, roleID string) (string, error) {
	secret := GetJWTSecret()
	now := time.Now()

	header := `{"alg":"HS256","typ":"JWT"}`
	claims := fmt.Sprintf(`{"token_type":"jwt","user_id":"%s","role_id":"%s","username":"%s","exp":%d,"iat":%d}`,
		userID, roleID, username, now.Add(24*time.Hour).Unix(), now.Unix())

	headerB64 := base64URLEncode([]byte(header))
	claimsB64 := base64URLEncode([]byte(claims))

	signingInput := headerB64 + "." + claimsB64
	sig := hmacSHA256([]byte(secret), []byte(signingInput))
	sigB64 := base64URLEncode(sig)

	return signingInput + "." + sigB64, nil
}

// ValidateToken checks the token signature and expiration, then returns the username.
// The current parser extracts fields textually rather than validating a complete JWT schema.
func ValidateToken(tokenString string) (string, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return "", errors.New("invalid token format")
	}

	// Verify the signature over the encoded header and payload.
	secret := GetJWTSecret()
	signingInput := parts[0] + "." + parts[1]
	sig := hmacSHA256([]byte(secret), []byte(signingInput))
	expectedSig := base64URLEncode(sig)

	if parts[2] != expectedSig {
		return "", errors.New("invalid token signature")
	}

	// Decode the payload after signature verification.
	claimsJSON, err := base64URLDecode(parts[1])
	if err != nil {
		return "", errors.New("invalid token payload")
	}

	claimsStr := string(claimsJSON)

	// Extract the username using the package's lightweight string parser.
	username := extractJSONValue(claimsStr, "username")
	if username == "" {
		return "", errors.New("invalid token: missing username")
	}

	// Reject an expired token when a positive exp value can be parsed.
	exp := extractJSONValue(claimsStr, "exp")
	if exp != "" {
		expTime := parseInt64(exp)
		if expTime > 0 && time.Now().Unix() > expTime {
			return "", errors.New("token expired")
		}
	}

	return username, nil
}

// ValidateTokenWithRole validates the signature and returns the supported identity and role fields.
// It shares the textual claim parser and does not validate every registered JWT claim.
func ValidateTokenWithRole(tokenString string) (*JWTClaims, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid token format")
	}

	secret := GetJWTSecret()
	signingInput := parts[0] + "." + parts[1]
	sig := hmacSHA256([]byte(secret), []byte(signingInput))
	expectedSig := base64URLEncode(sig)

	if parts[2] != expectedSig {
		return nil, errors.New("invalid token signature")
	}

	claimsJSON, err := base64URLDecode(parts[1])
	if err != nil {
		return nil, errors.New("invalid token payload")
	}

	claimsStr := string(claimsJSON)

	claims := &JWTClaims{
		Username:  extractJSONValue(claimsStr, "username"),
		TokenType: extractJSONValue(claimsStr, "token_type"),
		UserID:    extractJSONValue(claimsStr, "user_id"),
		RoleID:    extractJSONValue(claimsStr, "role_id"),
	}

	if claims.Username == "" {
		return nil, errors.New("invalid token: missing username")
	}

	exp := extractJSONValue(claimsStr, "exp")
	if exp != "" {
		claims.Exp = parseInt64(exp)
		if claims.Exp > 0 && time.Now().Unix() > claims.Exp {
			return nil, errors.New("token expired")
		}
	}

	return claims, nil
}

// CheckPassword supports legacy plaintext values and unsalted SHA-256 hex digests.
// Neither format is suitable for storing new passwords; prefer a password-hashing KDF such as Argon2id.
func CheckPassword(password, stored string) bool {
	if password == stored {
		return true
	}

	// Treat a 64-character stored value as a candidate SHA-256 hex digest.
	if len(stored) == 64 {
		h := sha256.Sum256([]byte(password))
		return hex.EncodeToString(h[:]) == stored
	}

	return false
}

// HashPassword returns an unsalted SHA-256 hex digest for legacy compatibility only.
// Do not use this helper for new password storage.
func HashPassword(password string) string {
	h := sha256.Sum256([]byte(password))
	return hex.EncodeToString(h[:])
}

// Internal encoding, signature, and claim-parsing helpers.

func base64URLEncode(data []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(data), "=")
}

// base64URLDecode decodes unpadded URL-safe Base64.
func base64URLDecode(s string) ([]byte, error) {
	// Restore the padding omitted by base64URLEncode.
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}
	return base64.URLEncoding.DecodeString(s)
}

// hmacSHA256 computes an HMAC-SHA256 message authentication code.
func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// extractJSONValue performs a minimal textual lookup for a string or number field.
// It is not a JSON parser: escaped quotes, nested objects, whitespace variations, and duplicate keys
// may be handled incorrectly. Use encoding/json before relying on untrusted token payloads.
func extractJSONValue(json string, key string) string {
	search := `"` + key + `":"`
	idx := strings.Index(json, search)
	if idx < 0 {
		// Try number value
		search = `"` + key + `":`
		idx = strings.Index(json, search)
		if idx < 0 {
			return ""
		}
		idx += len(search)
		end := strings.IndexAny(json[idx:], ",\n\r }")
		if end < 0 {
			return json[idx:]
		}
		val := strings.TrimSpace(json[idx : idx+end])
		return val
	}
	idx += len(search)
	end := strings.IndexByte(json[idx:], '"')
	if end < 0 {
		return ""
	}
	return json[idx : idx+end]
}

// parseInt64 parses the leading decimal digits; it does not report overflow or trailing characters.
func parseInt64(s string) int64 {
	var n int64
	for _, c := range s {
		if c >= '0' && c <= '9' {
			n = n*10 + int64(c-'0')
		} else {
			break
		}
	}
	return n
}
