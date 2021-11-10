package cred

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"strconv"
	"strings"

	mt "math/rand"
)

const (
	saltSize           = 16
	delimiter          = "$"
	stretchingPassword = 500
	saltLocalSecret    = "ahfw*&TGdsfnbi*^Wt"
)

type BookstackSaltCredManager struct{}

func NewBookstackSaltCredManager() *BookstackSaltCredManager {
	cm := &BookstackSaltCredManager{}
	return cm
}

func trimBookstackSalt(salt string) map[string]string {
	str := strings.Split(salt, delimiter)
	return map[string]string{
		"salt_secret":       str[0],
		"interation_string": str[1],
		"salt":              str[2],
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

func salt(secret string) (string, error) {

	buf := make([]byte, saltSize, saltSize+md5.Size)
	_, err := io.ReadFull(rand.Reader, buf)
	if err != nil {
		return "", err
	}

	hash := md5.New()
	hash.Write(buf)
	hash.Write([]byte(secret))
	return hex.EncodeToString(hash.Sum(buf)), nil
}

func saltSecret() (string, error) {
	rb := make([]byte, randInt(10, 100))
	_, err := rand.Read(rb)
	if err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(rb), nil
}

func randInt(min int, max int) int {
	return min + mt.Intn(max-min)
}

func (cm *BookstackSaltCredManager) GenerateUserSalt() string {
	saltSecret, err := saltSecret()
	if err != nil {
		return ""
	}

	salt, err := salt(saltLocalSecret + saltSecret)
	if err != nil {
		return ""
	}

	interation := randInt(1, 20)
	interationStr := strconv.Itoa(interation)

	return saltSecret + delimiter + interationStr + delimiter + salt
}

func (cm *BookstackSaltCredManager) CheckSealedPassword(password string, sealedPassword string) bool {
	currentPassword, err := ParseStandardPassword(sealedPassword)
	if err != nil {
		panic(err)
	}

	if len(currentPassword.Chunk) < 4 {
		panic(errors.New(StandardPasswordInvalidError))
	}

	data := map[string]string {
		"salt_secret":       currentPassword.Chunk[0],
		"interation_string": currentPassword.Chunk[1],
		"hash":              currentPassword.Chunk[2],
		"salt":              currentPassword.Chunk[3],
	}

	interation, _ := strconv.ParseInt(data["interation_string"], 10, 64)

	passwordHash, err := getBookstackHexDigest(password, data["salt_secret"], data["salt"], int64(interation))
	if err != nil {
		panic(err)
	}

	return passwordHash == data["hash"]
}

func (cm *BookstackSaltCredManager) GetSealedPassword(password string, organizationSalt string) string {
	saltSecret, err := saltSecret()
	if err != nil {
		panic(err)
	}

	salt, err := salt(saltLocalSecret + saltSecret)
	if err != nil {
		panic(err)
	}

	interation := randInt(1, 20)

	hash, err := getBookstackHexDigest(password, saltSecret, salt, int64(interation))
	if err != nil {
		panic(err)
	}

	interationStr := strconv.Itoa(interation)
	passwordHash := "$bookstack-salt$" + saltSecret + delimiter + interationStr + delimiter + hash + delimiter + salt

	return passwordHash
}
