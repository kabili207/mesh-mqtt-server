package hooks

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"

	"github.com/kabili207/mesh-mqtt-server/pkg/models"
)

type hashPair struct {
	Hash string
	Salt string
}

func hashPasswordWithSalt(password, salt string) string {
	hasher := sha256.New()
	hasher.Write([]byte(password + salt))
	return hex.EncodeToString(hasher.Sum(nil))
}

func (h *MeshtasticHook) validateUser(user, pass string) *models.User {
	u, err := h.config.Storage.Users.GetByUserName(user)
	if err != nil {
		h.Log.Error("unable to query mqtt user", "hook", h.ID(), "user", user, "error", err)
		return nil
	}

	if u == nil {
		return nil
	}
	if hashPasswordWithSalt(pass, u.Salt) == u.PasswordHash {
		return u
	}
	return nil
}

func randomHex(n int) (string, error) {
	bytes := make([]byte, n)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func generateHashAndSalt(password string) (hash string, salt string) {
	salt, _ = randomHex(16)
	hash = hashPasswordWithSalt(password, salt)
	return
}
