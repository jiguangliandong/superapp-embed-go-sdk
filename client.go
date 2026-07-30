package embedsdk

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const assertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

// Client 是 Partner Backend 使用的 Superapp Embed SSO 客户端。
type Client struct {
	BaseURL    string
	ClientID   string
	KeyID      string
	PrivateKey crypto.Signer
	HTTPClient *http.Client
	Now        func() time.Time
}

type Token struct {
	TokenType             string `json:"token_type"`
	AccessToken           string `json:"access_token"`
	ExpiresIn             int64  `json:"expires_in"`
	RefreshToken          string `json:"refresh_token"`
	RefreshTokenExpiresIn int64  `json:"refresh_token_expires_in"`
	Scope                 string `json:"scope"`
	OpenID                string `json:"open_id"`
	ConsentVersion        int    `json:"consent_version"`
}

type UserInfo struct {
	OpenID             string     `json:"open_id"`
	DisplayName        *string    `json:"display_name,omitempty"`
	AvatarURL          *string    `json:"avatar_url,omitempty"`
	AvatarURLExpiresAt *time.Time `json:"avatar_url_expires_at,omitempty"`
	ContactEmail       *string    `json:"contact_email,omitempty"`
	ContactPhone       *string    `json:"contact_phone,omitempty"`
	KYCStatus          *string    `json:"kyc_status,omitempty"`
}

type ProtocolError struct {
	Code        string `json:"error"`
	Description string `json:"error_description"`
	Status      int    `json:"-"`
}

func (err *ProtocolError) Error() string {
	if err.Description == "" {
		return err.Code
	}
	return err.Code + ": " + err.Description
}

func (client *Client) ExchangeAuthorizationCode(
	ctx context.Context,
	code, codeVerifier string,
) (Token, error) {
	return client.token(ctx, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"code_verifier": {codeVerifier},
	})
}

func (client *Client) Refresh(ctx context.Context, refreshToken string) (Token, error) {
	return client.token(ctx, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
	})
}

func (client *Client) Revoke(ctx context.Context, token string) error {
	endpoint := strings.TrimRight(client.BaseURL, "/") + "/api/embed/v1/oauth/revoke"
	values := url.Values{"token": {token}}
	if err := client.authenticateForm(values, endpoint); err != nil {
		return err
	}
	response, err := client.doForm(ctx, endpoint, values)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return decodeProtocolError(response)
	}
	return nil
}

func (client *Client) UserInfo(ctx context.Context, accessToken string) (UserInfo, error) {
	endpoint := strings.TrimRight(client.BaseURL, "/") + "/api/embed/v1/userinfo"
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return UserInfo{}, err
	}
	request.Header.Set("Authorization", "Bearer "+accessToken)
	response, err := client.httpClient().Do(request)
	if err != nil {
		return UserInfo{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return UserInfo{}, decodeProtocolError(response)
	}
	var result UserInfo
	if err := decodeJSON(response.Body, &result); err != nil {
		return UserInfo{}, err
	}
	return result, nil
}

func (client *Client) token(ctx context.Context, values url.Values) (Token, error) {
	endpoint := strings.TrimRight(client.BaseURL, "/") + "/api/embed/v1/oauth/token"
	if err := client.authenticateForm(values, endpoint); err != nil {
		return Token{}, err
	}
	response, err := client.doForm(ctx, endpoint, values)
	if err != nil {
		return Token{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return Token{}, decodeProtocolError(response)
	}
	var result Token
	if err := decodeJSON(response.Body, &result); err != nil {
		return Token{}, err
	}
	return result, nil
}

func (client *Client) authenticateForm(values url.Values, audience string) error {
	assertion, err := client.clientAssertion(audience)
	if err != nil {
		return err
	}
	values.Set("client_id", client.ClientID)
	values.Set("client_assertion_type", assertionType)
	values.Set("client_assertion", assertion)
	return nil
}

func (client *Client) clientAssertion(audience string) (string, error) {
	if client.PrivateKey == nil || client.ClientID == "" || client.KeyID == "" {
		return "", errors.New("client ID, key ID, and private key are required")
	}
	algorithm := ""
	switch client.PrivateKey.Public().(type) {
	case *ecdsa.PublicKey:
		algorithm = "ES256"
	case *rsa.PublicKey:
		algorithm = "RS256"
	default:
		return "", errors.New("only ES256 and RS256 private keys are supported")
	}
	now := client.now().UTC()
	jti, err := randomValue(24)
	if err != nil {
		return "", err
	}
	header, _ := json.Marshal(map[string]string{"alg": algorithm, "kid": client.KeyID, "typ": "JWT"})
	claims, _ := json.Marshal(map[string]any{
		"iss": client.ClientID, "sub": client.ClientID, "aud": audience,
		"iat": now.Unix(), "exp": now.Add(2 * time.Minute).Unix(), "jti": jti,
	})
	signingInput := encodeSegment(header) + "." + encodeSegment(claims)
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := client.PrivateKey.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		return "", err
	}
	if algorithm == "ES256" {
		var parsed struct{ R, S *big.Int }
		if rest, parseErr := asn1.Unmarshal(signature, &parsed); parseErr != nil ||
			len(rest) != 0 || parsed.R == nil || parsed.S == nil {
			return "", errors.New("ES256 signer returned an invalid ASN.1 signature")
		}
		signature = fixedWidthECDSASignature(parsed.R, parsed.S, 32)
	}
	return signingInput + "." + encodeSegment(signature), nil
}

func (client *Client) doForm(ctx context.Context, endpoint string, values url.Values) (*http.Response, error) {
	request, err := http.NewRequestWithContext(
		ctx, http.MethodPost, endpoint, strings.NewReader(values.Encode()),
	)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/json")
	return client.httpClient().Do(request)
}

func (client *Client) httpClient() *http.Client {
	if client.HTTPClient != nil {
		return client.HTTPClient
	}
	return http.DefaultClient
}

func (client *Client) now() time.Time {
	if client.Now != nil {
		return client.Now()
	}
	return time.Now()
}

func decodeProtocolError(response *http.Response) error {
	var result ProtocolError
	result.Status = response.StatusCode
	if err := decodeJSON(response.Body, &result); err != nil {
		return fmt.Errorf("Superapp Embed endpoint returned HTTP %d", response.StatusCode)
	}
	return &result
}

func decodeJSON(reader io.Reader, target any) error {
	decoder := json.NewDecoder(io.LimitReader(reader, 1<<20))
	decoder.DisallowUnknownFields()
	return decoder.Decode(target)
}

func encodeSegment(value []byte) string {
	return base64.RawURLEncoding.EncodeToString(value)
}

func fixedWidthECDSASignature(r, s *big.Int, size int) []byte {
	result := make([]byte, size*2)
	r.FillBytes(result[:size])
	s.FillBytes(result[size:])
	return result
}

// PublicJWK 返回可登记到 Superapp Admin API 的公钥 JWK。
func PublicJWK(signer crypto.Signer, keyID string) (json.RawMessage, error) {
	switch key := signer.Public().(type) {
	case *ecdsa.PublicKey:
		if key.Curve != elliptic.P256() {
			return nil, errors.New("only P-256 is supported for ES256")
		}
		return json.Marshal(map[string]string{
			"kty": "EC", "crv": "P-256", "use": "sig", "alg": "ES256", "kid": keyID,
			"x": encodeSegment(key.X.FillBytes(make([]byte, 32))),
			"y": encodeSegment(key.Y.FillBytes(make([]byte, 32))),
		})
	case *rsa.PublicKey:
		return json.Marshal(map[string]string{
			"kty": "RSA", "use": "sig", "alg": "RS256", "kid": keyID,
			"n": encodeSegment(key.N.Bytes()),
			"e": encodeSegment(big.NewInt(int64(key.E)).Bytes()),
		})
	default:
		return nil, errors.New("unsupported public key type")
	}
}
