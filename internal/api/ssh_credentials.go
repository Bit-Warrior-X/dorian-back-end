package api

import (
	"errors"
	"strings"

	"vue-project-backend/internal/remotesvc"
	"vue-project-backend/internal/store"
)

// normalizeSSHAuthType maps the requested type to password or key. A blank type
// falls back to key when one was supplied, so older clients keep working.
func normalizeSSHAuthType(authType, privateKey string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(authType)) {
	case store.SSHAuthPassword:
		return store.SSHAuthPassword, nil
	case store.SSHAuthKey:
		return store.SSHAuthKey, nil
	case "":
		return store.SSHAuthTypeOf(privateKey), nil
	default:
		return "", errors.New(`sshAuthType must be "password" or "key"`)
	}
}

// applySSHCredentials keeps only the credential for the chosen auth type and checks
// that it is present (and, for a key, that it parses with the given passphrase).
func applySSHCredentials(authType string, password, privateKey, passphrase *string) error {
	*password = strings.TrimSpace(*password)
	*privateKey = strings.TrimSpace(*privateKey)
	kind, err := normalizeSSHAuthType(authType, *privateKey)
	if err != nil {
		return err
	}
	if kind == store.SSHAuthKey {
		*password = ""
		if *privateKey == "" {
			return errors.New("an SSH private key is required for key authentication")
		}
		_, err := remotesvc.ParsePrivateKey(*privateKey, *passphrase)
		return err
	}
	*privateKey, *passphrase = "", ""
	if *password == "" {
		return errors.New("an SSH password is required for password authentication")
	}
	return nil
}

type sshCredentialUpdate struct {
	password      string
	privateKey    string
	passphrase    string
	clearKey      bool
	clearPassword bool
}

// resolveSSHCredentialUpdate applies an edit to an edge's SSH credentials. Blank
// secrets keep the stored value; switching auth type deletes the other credential,
// and the edge must always end up with the credential its type needs.
func resolveSSHCredentialUpdate(before store.ServerView, payload serverUpdatePayload) (sshCredentialUpdate, error) {
	update := sshCredentialUpdate{
		password:   strings.TrimSpace(payload.SSHPassword),
		privateKey: strings.TrimSpace(payload.SSHPrivateKey),
		passphrase: payload.SSHKeyPassphrase,
	}
	kind := before.SSHAuthType
	if strings.TrimSpace(payload.SSHAuthType) != "" {
		var err error
		if kind, err = normalizeSSHAuthType(payload.SSHAuthType, ""); err != nil {
			return update, err
		}
	} else if update.privateKey != "" {
		kind = store.SSHAuthKey
	}

	if kind == store.SSHAuthKey {
		update.password, update.clearPassword = "", true
		keyToCheck := update.privateKey
		if keyToCheck == "" {
			keyToCheck = before.SSHPrivateKey
		}
		if keyToCheck == "" {
			return update, errors.New("an SSH private key is required for key authentication")
		}
		if update.privateKey != "" || update.passphrase != "" {
			if _, err := remotesvc.ParsePrivateKey(keyToCheck, update.passphrase); err != nil {
				return update, err
			}
		}
		return update, nil
	}

	update.privateKey, update.passphrase, update.clearKey = "", "", true
	if update.password == "" && before.SSHPassword == "" {
		return update, errors.New("an SSH password is required for password authentication")
	}
	return update, nil
}
