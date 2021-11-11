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

package object

import (
	"crypto/tls"
	"net/http"
	"strings"

	"github.com/casbin/casdoor/util"
)

func sendWebhook(webhook *Webhook, record *Record) error {
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	body := strings.NewReader(util.StructToJson(record))

	req, err := http.NewRequest("POST", webhook.Url, body)
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", webhook.ContentType)

	_, err = client.Do(req)
	return err
}
