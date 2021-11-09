package cred

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"strconv"
	"strings"
)

const (
	saltSize           = 16
	delimiter          = "$"
	stretchingPassword = 500
	saltLocalSecret    = "ahfw*&TGdsfnbi*^Wt"
)

type BookstackSaltCredManager struct {}

func NewBookstackSaltCredManager() *BookstackSaltCredManager {
	cm := &BookstackSaltCredManager{}
	return cm
}

func trimBookstackSalt(salt string) map[string]string {
	str := strings.Split(salt, delimiter)
	return map[string]string{
		"salt_secret":       str[0],
		"interation_string": str[1],
		"salt":              str[3],
	}
}

func getBookstackHexDigest(pass string, saltSecret string, salt string, interation int64) (string, error) {
	var passSalt = saltSecret + pass + salt + saltSecret + pass + salt + pass + pass + salt
	var i int

	hashPass := saltLocalSecret
	hashStart := sha512.New()
	hashCenter := sha256.New()
	hashOutput := sha256.New224()

	i = 0
	for i <= stretchingPassword {
		i = i + 1
		hashStart.Write([]byte(passSalt + hashPass))
		hashPass = hex.EncodeToString(hashStart.Sum(nil))
	}

	i = 0
	for int64(i) <= interation {
		i = i + 1
		hashPass = hashPass + hashPass
	}

	i = 0
	for i <= stretchingPassword {
		i = i + 1
		hashCenter.Write([]byte(hashPass + saltSecret))
		hashPass = hex.EncodeToString(hashCenter.Sum(nil))
	}
	hashOutput.Write([]byte(hashPass + saltLocalSecret))
	hashPass = hex.EncodeToString(hashOutput.Sum(nil))

	return hashPass, nil
}

func (cm *BookstackSaltCredManager) GetSealedPassword(password string, userSalt string, organizationSalt string) string {
	if userSalt == "" {
		return NewSha256SaltCredManager().GetSealedPassword(password, userSalt, organizationSalt)
	} else {
		data := trimBookstackSalt(userSalt)
		interation, _ := strconv.ParseInt(data["interation_string"], 10, 64)
		hashResult, err := getBookstackHexDigest(password, data["salt_secret"], data["salt"], interation)
		if err != nil {
			return ""
		}
		return hashResult
	}
}
