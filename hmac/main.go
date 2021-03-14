package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"fmt"
	"io"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
)

type UserClaims struct {
	jwt.StandardClaims
	SessionID int64
}

func (u *UserClaims) Valid() error {
	// checks whether the token expired or not. returns bool
	if !u.VerifyExpiresAt(time.Now().Unix(), true) {
		return fmt.Errorf("Token has expired")
	}

	if u.SessionID == 0 {
		return fmt.Errorf("invalid session ID")
	}

	return nil
}

func main() {

}

func signMessage(msg []byte) ([]byte, error) {
	// second arg is a private key, key needs to be the same size as hasher
	// sha512 is 64 bits
	h := hmac.New(sha512.New, keys[currentKid].key)

	// hash is a writer
	_, err := h.Write(msg)
	if err != nil {
		return nil, fmt.Errorf("Error in signMessage while hashing message: %w", err)
	}

	// returns signature value
	signature := h.Sum(nil)

	return signature, nil
}

func checkSig(msg, sig []byte) (bool, error) {
	// sign message
	newSig, err := signMessage(msg)
	if err != nil {
		return false, fmt.Errorf("Error verifying signature: %w", err)
	}

	// compare it
	return hmac.Equal(newSig, sig), nil
}

func createToken(c *UserClaims) (string, error) {
	// creates the base token
	t := jwt.NewWithClaims(jwt.SigningMethodHS512, c)

	// pass in signing key. returns signed token and error
	signedToken, err := t.SignedString(keys[currentKid].key)
	if err != nil {
		return "", fmt.Errorf("Problem generating signed token: %w", err)
	}

	return signedToken, nil
}

func generateNewKey() error {
	// generates the most random key that your computer can make
	newKey := make([]byte, 64)
	_, err := io.ReadFull(rand.Reader, newKey)
	if err != nil {
		return fmt.Errorf("Error generating key: %w", err)
	}

	// generates a new UUID or panics
	uid := uuid.New()
	keys[uid.String()] = key{
		key:     newKey,
		created: time.Now(),
	}

	currentKid = uid.String()
	return nil
}

type key struct {
	key     []byte
	created time.Time
}

var currentKid = ""
var keys = map[string]key{}

func parseToken(signedToken string) (*UserClaims, error) {
	// 3rd arg is a key func
	t, err := jwt.ParseWithClaims(signedToken, &UserClaims{}, func(t *jwt.Token) (interface{}, error) {
		// the token is not yet verified, we will verify the token in this function
		if t.Method.Alg() != jwt.SigningMethodHS512.Alg() {
			// not the same signing algorithm(algorithms need to match)
			return nil, fmt.Errorf("Invalid signing algorithm")
		}

		// you can use key id to decide which key you want to use
		kid, ok := t.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("Invalid key ID")
		}

		k, ok := keys[kid]

		if !ok {
			return nil, fmt.Errorf("invalid key ID")
		}
		// in this case, the expected key, is our key
		return k.key, nil
		// return key, nil

	})

	if err != nil {
		return nil, fmt.Errorf("Failed to parse token: %w", err)
	}

	if !t.Valid {
		return nil, fmt.Errorf("Error in parse token, token is not valid")
	}

	// assert that the tokens claims matches UserClaims
	return t.Claims.(*UserClaims), nil
}
