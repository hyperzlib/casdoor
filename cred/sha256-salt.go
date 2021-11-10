// Copyright 2021 The casbin Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cred

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/thanhpk/randstr"
)

type Sha256SaltCredManager struct{}

func generateSha256UserSalt() string {
	return randstr.Hex(8)
}

func getSha256(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

func getSha256HexDigest(s string) string {
	b := getSha256([]byte(s))
	res := hex.EncodeToString(b)
	return res
}

func NewSha256SaltCredManager() *Sha256SaltCredManager {
	cm := &Sha256SaltCredManager{}
	return cm
}

func (cm *Sha256SaltCredManager) GetSealedPassword(password string, organizationSalt string) string {
	res := new(StandardPassword)
	res.Type = "sha256-salt"
	res.OrganizationSalt = organizationSalt
	res.UserSalt = generateSha256UserSalt()

	hash := getSha256HexDigest(password)
	hash = getSha256HexDigest(hash + res.UserSalt)
	if res.OrganizationSalt != "" {
		hash = getSha256HexDigest(hash + res.OrganizationSalt)
	}
	res.PasswordHash = hash

	return res.String()
}

func (cm *Sha256SaltCredManager) CheckSealedPassword(password string, sealedPassword string) bool {
	currentPassword, err := ParseStandardPassword(sealedPassword)
	if err != nil {
		panic(err)
	}

	hash := getSha256HexDigest(password)
	if currentPassword.UserSalt != "" {
		hash = getSha256HexDigest(hash + currentPassword.UserSalt)
	}
	if currentPassword.OrganizationSalt != "" {
		hash = getSha256HexDigest(hash + currentPassword.OrganizationSalt)
	}
	return hash == currentPassword.PasswordHash
}
