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

package idp

import (
	"net/http"
	"strings"

	"golang.org/x/oauth2"
)

type UserInfo struct {
	Id          string
	Username    string
	DisplayName string
	Email       string
	AvatarUrl   string
}

type IdProvider interface {
	SetHttpClient(client *http.Client)
	GetToken(code string) (*oauth2.Token, error)
	GetUserInfo(token *oauth2.Token) (*UserInfo, error)
}

func GetIdProvider(providerType string, clientId string, clientSecret string, redirectUrl string) IdProvider {
	if providerType == "GitHub" {
		return NewGithubIdProvider(clientId, clientSecret, redirectUrl)
	} else if providerType == "Google" {
		return NewGoogleIdProvider(clientId, clientSecret, redirectUrl)
	} else if providerType == "QQ" {
		return NewQqIdProvider(clientId, clientSecret, redirectUrl)
	} else if providerType == "WeChat" {
		return NewWeChatIdProvider(clientId, clientSecret, redirectUrl)
	} else if providerType == "Facebook" {
		return NewFacebookIdProvider(clientId, clientSecret, redirectUrl)
	} else if providerType == "DingTalk" {
		return NewDingTalkIdProvider(clientId, clientSecret, redirectUrl)
	} else if providerType == "Weibo" {
		return NewWeiBoIdProvider(clientId, clientSecret, redirectUrl)
	} else if providerType == "Gitee" {
		return NewGiteeIdProvider(clientId, clientSecret, redirectUrl)
	} else if providerType == "LinkedIn" {
		return NewLinkedInIdProvider(clientId, clientSecret, redirectUrl)
	} else if providerType == "WeCom" {
		return NewWeComIdProvider(clientId, clientSecret, redirectUrl)
	} else if providerType == "Lark" {
		return NewLarkIdProvider(clientId, clientSecret, redirectUrl)
	} else if providerType == "GitLab" {
		return NewGitlabIdProvider(clientId, clientSecret, redirectUrl)
	} else if isGothSupport(providerType) {
		return NewGothIdProvider(providerType, clientId, clientSecret, redirectUrl)
	}

	return nil
}

var gothList = []string{"Apple", "AzureAd", "Slack"}

func isGothSupport(provider string) bool {
	for _, value := range gothList {
		if strings.EqualFold(value, provider) {
			return true
		}
	}
	return false
}
