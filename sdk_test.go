package embedsdk

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestTransactionManagerKeepsVerifierServerSide(t *testing.T) {
	manager := NewTransactionManager("embcli_demo", NewMemoryTransactionStore(), time.Minute)
	bootstrap, err := manager.Begin(context.Background(), "partner-session-1", []string{"auth_base"})
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(bootstrap)
	if strings.Contains(string(encoded), "verifier") {
		t.Fatalf("bootstrap leaked verifier: %s", encoded)
	}
	transaction, err := manager.Complete(
		context.Background(), bootstrap.TransactionID, bootstrap.State, "partner-session-1",
	)
	if err != nil {
		t.Fatal(err)
	}
	if transaction.CodeVerifier == "" {
		t.Fatal("server-side transaction must retain verifier")
	}
	if _, err := manager.Complete(
		context.Background(), bootstrap.TransactionID, bootstrap.State, "partner-session-1",
	); err == nil {
		t.Fatal("transaction should be one-time")
	}
}

func TestTransactionManagerConsumesTransactionOnBindingMismatch(t *testing.T) {
	manager := NewTransactionManager("embcli_demo", NewMemoryTransactionStore(), time.Minute)
	bootstrap, err := manager.Begin(context.Background(), "session-a", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Complete(
		context.Background(), bootstrap.TransactionID, bootstrap.State, "session-b",
	); err == nil {
		t.Fatal("另一浏览器 Session 不得完成登录交易")
	}
	if _, err := manager.Complete(
		context.Background(), bootstrap.TransactionID, bootstrap.State, "session-a",
	); err == nil {
		t.Fatal("绑定校验失败后交易也必须保持一次性")
	}
}

func TestExchangeUsesPrivateKeyJWT(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/api/user/v1/open/embed/oauth/token" {
			t.Errorf("path = %q", request.URL.Path)
		}
		if err := request.ParseForm(); err != nil {
			t.Fatal(err)
		}
		if strings.Count(request.Form.Get("client_assertion"), ".") != 2 {
			t.Errorf("missing signed client assertion")
		}
		if request.Form.Get("code_verifier") != "verifier" {
			t.Errorf("code_verifier = %q", request.Form.Get("code_verifier"))
		}
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write([]byte(`{"token_type":"Bearer","access_token":"at","expires_in":900,"refresh_token":"rt","refresh_token_expires_in":3600,"scope":"auth_base","open_id":"eoi_1","consent_version":1}`))
	}))
	defer server.Close()

	client := Client{BaseURL: server.URL, ClientID: "embcli_1", KeyID: "key-1", PrivateKey: key}
	token, err := client.ExchangeAuthorizationCode(context.Background(), "code", "verifier")
	if err != nil {
		t.Fatal(err)
	}
	if token.OpenID != "eoi_1" {
		t.Fatalf("open_id = %q", token.OpenID)
	}
}

func TestUserInfoDecodesStableAvatarURL(t *testing.T) {
	const avatarURL = "https://media.superapp.example/assets/avatar/file_01KTEST"
	server := httptest.NewServer(http.HandlerFunc(func(
		response http.ResponseWriter,
		request *http.Request,
	) {
		if request.URL.Path != "/api/user/v1/open/embed/userinfo" {
			t.Errorf("path = %q", request.URL.Path)
		}
		if request.Header.Get("Authorization") != "Bearer access-token" {
			t.Errorf("Authorization = %q", request.Header.Get("Authorization"))
		}
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write([]byte(
			`{"open_id":"eoi_1","display_name":"Example User","avatar_url":"` +
				avatarURL + `"}`,
		))
	}))
	defer server.Close()

	client := Client{BaseURL: server.URL}
	userinfo, err := client.UserInfo(context.Background(), "access-token")
	if err != nil {
		t.Fatal(err)
	}
	if userinfo.AvatarURL == nil || *userinfo.AvatarURL != avatarURL {
		t.Fatalf("avatar URL = %v", userinfo.AvatarURL)
	}
}
