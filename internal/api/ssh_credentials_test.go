package api

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"vue-project-backend/internal/remotesvc"
	"vue-project-backend/internal/store"
)

func testPrivateKeyPEM(t *testing.T, passphrase string) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var block *pem.Block
	if passphrase == "" {
		block, err = ssh.MarshalPrivateKey(priv, "")
	} else {
		block, err = ssh.MarshalPrivateKeyWithPassphrase(priv, "", []byte(passphrase))
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(block))
}

func TestApplySSHCredentials(t *testing.T) {
	key := testPrivateKeyPEM(t, "")

	pass, k, pp := "secret", key, "ignored"
	if err := applySSHCredentials("password", &pass, &k, &pp); err != nil {
		t.Fatalf("password: %v", err)
	}
	if pass != "secret" || k != "" || pp != "" {
		t.Fatalf("password type must drop the key, got pass=%q key=%q pp=%q", pass, k, pp)
	}

	pass, k, pp = "secret", key, ""
	if err := applySSHCredentials("key", &pass, &k, &pp); err != nil {
		t.Fatalf("key: %v", err)
	}
	if pass != "" || k == "" {
		t.Fatalf("key type must drop the password, got pass=%q", pass)
	}

	pass, k, pp = "", key, ""
	if err := applySSHCredentials("", &pass, &k, &pp); err != nil {
		t.Fatalf("blank type with key should infer key: %v", err)
	}

	for _, tc := range []struct{ authType, pass, key string }{
		{"password", "", key},
		{"key", "secret", ""},
		{"", "", ""},
		{"token", "secret", ""},
		{"key", "", "not a key"},
	} {
		p, k, pp := tc.pass, tc.key, ""
		if err := applySSHCredentials(tc.authType, &p, &k, &pp); err == nil {
			t.Errorf("type=%q pass=%q key-set=%v: expected an error", tc.authType, tc.pass, tc.key != "")
		}
	}
}

func TestResolveSSHCredentialUpdate(t *testing.T) {
	key := testPrivateKeyPEM(t, "")
	passwordEdge := store.ServerView{SSHPassword: "old", SSHAuthType: store.SSHAuthPassword}
	keyEdge := store.ServerView{SSHPrivateKey: key, SSHAuthType: store.SSHAuthKey}

	// Unchanged password edge: blank password keeps it.
	got, err := resolveSSHCredentialUpdate(passwordEdge, serverUpdatePayload{})
	if err != nil || got.clearPassword || !got.clearKey {
		t.Fatalf("keep password: %+v %v", got, err)
	}

	// Switch to key without supplying one fails; with one it clears the password.
	if _, err := resolveSSHCredentialUpdate(passwordEdge, serverUpdatePayload{SSHAuthType: "key"}); err == nil {
		t.Fatal("switch to key without a key should fail")
	}
	got, err = resolveSSHCredentialUpdate(passwordEdge, serverUpdatePayload{SSHAuthType: "key", SSHPrivateKey: key})
	if err != nil || !got.clearPassword || got.clearKey || got.privateKey == "" {
		t.Fatalf("switch to key: %+v %v", got, err)
	}

	// Key edge: blank keeps the key; switching to password needs a new password.
	got, err = resolveSSHCredentialUpdate(keyEdge, serverUpdatePayload{SSHPassword: "ignored"})
	if err != nil || !got.clearPassword || got.password != "" || got.clearKey {
		t.Fatalf("keep key: %+v %v", got, err)
	}
	if _, err := resolveSSHCredentialUpdate(keyEdge, serverUpdatePayload{SSHAuthType: "password"}); err == nil {
		t.Fatal("switch to password without a password should fail")
	}
	got, err = resolveSSHCredentialUpdate(keyEdge, serverUpdatePayload{SSHAuthType: "password", SSHPassword: "new"})
	if err != nil || !got.clearKey || got.clearPassword || got.password != "new" {
		t.Fatalf("switch to password: %+v %v", got, err)
	}

	// Wrong passphrase for the stored key is rejected.
	if _, err := resolveSSHCredentialUpdate(keyEdge, serverUpdatePayload{SSHKeyPassphrase: "x"}); err == nil {
		t.Fatal("passphrase on an unencrypted key should fail")
	}
}

func TestUnencryptedPrivateKeyPEM(t *testing.T) {
	encrypted := testPrivateKeyPEM(t, "pp")
	if _, err := remotesvc.UnencryptedPrivateKeyPEM(encrypted, ""); err == nil {
		t.Fatal("missing passphrase should fail")
	}
	out, err := remotesvc.UnencryptedPrivateKeyPEM(encrypted, "pp")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "BEGIN OPENSSH PRIVATE KEY") {
		t.Fatalf("unexpected PEM: %q", out)
	}
	if _, err := ssh.ParsePrivateKey([]byte(out)); err != nil {
		t.Fatalf("output must parse without a passphrase: %v", err)
	}
	if out, err := remotesvc.UnencryptedPrivateKeyPEM("", ""); err != nil || out != "" {
		t.Fatalf("empty key: %q %v", out, err)
	}
}
